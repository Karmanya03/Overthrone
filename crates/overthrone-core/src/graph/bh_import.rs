use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use tracing::{info, warn};

use crate::error::{OverthroneError, Result};
use crate::graph::{AdNode, AttackGraph, EdgeType, NodeType};

// ═══════════════════════════════════════════════════════════════
//  SharpHound v2 JSON Structures
// ═══════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhContainer<T> {
    meta: BhMeta,
    data: Vec<T>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhMeta {
    #[serde(rename = "type")]
    object_type: String,
    count: usize,
    version: u32,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhUser {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(default)]
    properties: HashMap<String, serde_json::Value>,
    #[serde(default)]
    member_of: Vec<BhTypedPrincipal>,
    #[serde(default)]
    aces: Vec<BhAce>,
    #[serde(default)]
    spn_targets: Vec<BhTypedPrincipal>,
    #[serde(default)]
    has_sid_history: Vec<BhTypedPrincipal>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhComputer {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(default)]
    properties: HashMap<String, serde_json::Value>,
    #[serde(default)]
    member_of: Vec<BhTypedPrincipal>,
    #[serde(default)]
    aces: Vec<BhAce>,
    #[serde(default)]
    allowed_to_delegate: Vec<BhTypedPrincipal>,
    #[serde(default)]
    allowed_to_act: Vec<BhTypedPrincipal>,
    #[serde(default)]
    sessions: Vec<BhTypedPrincipal>,
    #[serde(default)]
    local_admins: Vec<BhTypedPrincipal>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhGroup {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(default)]
    properties: HashMap<String, serde_json::Value>,
    #[serde(default)]
    members: Vec<BhGroupMember>,
    #[serde(default)]
    aces: Vec<BhAce>,
    #[serde(default)]
    member_of: Vec<BhTypedPrincipal>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhDomain {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(default)]
    properties: HashMap<String, serde_json::Value>,
    #[serde(default)]
    trusts: Vec<BhTrust>,
    #[serde(default)]
    aces: Vec<BhAce>,
}

#[derive(Debug, Deserialize)]
struct BhGpo {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(default)]
    properties: HashMap<String, serde_json::Value>,
    #[serde(default)]
    aces: Vec<BhAce>,
}

#[derive(Debug, Deserialize)]
struct BhOu {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(default)]
    properties: HashMap<String, serde_json::Value>,
    #[serde(default)]
    aces: Vec<BhAce>,
    #[serde(default)]
    child_objects: Vec<BhTypedPrincipal>,
    #[serde(default)]
    links: Vec<BhTypedPrincipal>,
}

#[derive(Debug, Deserialize)]
struct BhTypedPrincipal {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
}

#[derive(Debug, Deserialize)]
struct BhGroupMember {
    #[serde(alias = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "MemberType", default)]
    member_type: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhAce {
    #[serde(alias = "PrincipalIdentifier")]
    principal_identifier: String,
    #[serde(alias = "RightName")]
    right_name: String,
    #[serde(alias = "AceType", default)]
    ace_type: Option<String>,
    #[serde(alias = "IsInherited", default)]
    is_inherited: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BhTrust {
    #[serde(alias = "TrustType")]
    trust_type: String,
    #[serde(alias = "IsTransitive", default)]
    is_transitive: bool,
    #[serde(alias = "SidFiltering", default)]
    sid_filtering: bool,
    #[serde(alias = "TargetDomainSid", default)]
    target_domain_sid: Option<String>,
    #[serde(alias = "TargetDomainName", default)]
    target_domain_name: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
//  Intermediate representation
// ═══════════════════════════════════════════════════════════════

struct BhImportGraph {
    nodes: HashMap<String, AdNode>,         // SID -> node
    edges: Vec<(String, String, EdgeType)>, // source_sid, target_sid, edge
    sid_to_name: HashMap<String, String>,   // SID -> "NAME@DOMAIN"
    name_to_sid: HashMap<String, String>,   // "NAME@DOMAIN" -> SID
    domain_nodes: Vec<String>,              // SIDs of domain nodes
}

// ═══════════════════════════════════════════════════════════════
//  BH Right Name -> EdgeType mapping
// ═══════════════════════════════════════════════════════════════

fn bh_right_to_edge(right: &str) -> Option<EdgeType> {
    match right.to_uppercase().as_str() {
        "GENERICALL" => Some(EdgeType::GenericAll),
        "GENERICWRITE" | "GENERIC_WRITE" => Some(EdgeType::GenericWrite),
        "WRITEDACL" | "WRITE_DACL" => Some(EdgeType::WriteDacl),
        "WRITEOWNER" | "WRITE_OWNER" => Some(EdgeType::WriteOwner),
        "OWNS" => Some(EdgeType::Owns),
        "ALLEXTENDEDRIGHTS" | "ALL_EXTENDED_RIGHTS" => Some(EdgeType::AllExtendedRights),
        "FORCECHANGEPASSWORD" | "FORCE_CHANGE_PASSWORD" => Some(EdgeType::ForceChangePassword),
        "ADDMEMBERS" | "ADD_MEMBER" | "WRITEMEMBER" => Some(EdgeType::AddMembers),
        "ADDSELF" | "ADD_SELF" => Some(EdgeType::AddSelf),
        "WRITESPIN" | "WRITE_SPN" => Some(EdgeType::WriteSPN),
        "WRITEKEYCREDENTIALLINK" | "WRITE_KEY_CREDENTIAL_LINK" => {
            Some(EdgeType::WriteKeyCredentialLink)
        }
        "ADDKEYCREDENTIALLINK" | "ADD_KEY_CREDENTIAL_LINK" => Some(EdgeType::AddKeyCredentialLink),
        "WRITEALLOWEDTODELEGATETO" | "WRITE_ALLOWED_TO_DELEGATE_TO" => {
            Some(EdgeType::WriteAllowedToDelegateTo)
        }
        "ADDALLOWEDTOACT" | "ADD_ALLOWED_TO_ACT" => Some(EdgeType::AddAllowedToAct),
        "WRITEACCOUNTRESTRICTIONS" | "WRITE_ACCOUNT_RESTRICTIONS" => {
            Some(EdgeType::WriteAccountRestrictions)
        }
        "GETCHANGES" | "GET_CHANGES" => Some(EdgeType::GetChanges),
        "GETCHANGESALL" | "GET_CHANGES_ALL" => Some(EdgeType::GetChangesAll),
        "ENROLL" => Some(EdgeType::Enroll),
        "READLAPSPASSWORD" | "READ_LAPS_PASSWORD" => Some(EdgeType::ReadLapsPassword),
        "READGMSAPASSWORD" | "READ_GMSA_PASSWORD" => Some(EdgeType::ReadGmsaPassword),
        "CANRDP" | "CAN_RDP" => Some(EdgeType::CanRDP),
        "CANPSREMOTE" | "CAN_PS_REMOTE" => Some(EdgeType::CanPSRemote),
        "EXECUTEDCOM" | "EXECUTE_DCOM" => Some(EdgeType::ExecuteDCOM),
        "SQLADMIN" | "HASSQLADMIN" => Some(EdgeType::SQLAdmin),
        "ALLOWEDTODELEGATE" | "ALLOWED_TO_DELEGATE" => Some(EdgeType::AllowedToDelegate),
        "CONTAINS" => Some(EdgeType::Contains),
        "GPLINK" | "GP_LINK" => Some(EdgeType::GpoLink),
        "TRUSTEDBY" | "TRUSTED_BY" => Some(EdgeType::TrustedBy),
        "HASSIDHISTORY" | "HAS_SID_HISTORY" => Some(EdgeType::HasSidHistory),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Property extraction helpers
// ═══════════════════════════════════════════════════════════════

fn get_string(props: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    props.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn get_bool(props: &HashMap<String, serde_json::Value>, key: &str) -> bool {
    props.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn extract_name(props: &HashMap<String, serde_json::Value>, sid: &str) -> String {
    if let Some(name) = get_string(props, "name") {
        if name.contains('@') {
            return name.to_uppercase();
        }
        if let Some(domain) = get_string(props, "domain") {
            return format!("{}@{}", name, domain).to_uppercase();
        }
        format!("{}@{}", name, sid)
    } else if let Some(sam) = get_string(props, "samaccountname") {
        if let Some(domain) = get_string(props, "domain") {
            return format!("{sam}@{domain}").to_uppercase();
        }
        format!("{sam}@{sid}")
    } else {
        sid.to_string()
    }
}

fn extract_domain(props: &HashMap<String, serde_json::Value>) -> String {
    get_string(props, "domain").unwrap_or_else(|| "UNKNOWN".to_string())
}

fn extract_dn(props: &HashMap<String, serde_json::Value>) -> Option<String> {
    get_string(props, "distinguishedname").or_else(|| get_string(props, "distinguishedname|dn"))
}

// ═══════════════════════════════════════════════════════════════
//  File loading
// ═══════════════════════════════════════════════════════════════

fn load_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        OverthroneError::custom(format!("IO error reading {}: {e}", path.display()))
    })?;
    serde_json::from_str(&content).map_err(|e| {
        OverthroneError::Custom(format!("JSON parse error in {}: {e}", path.display()))
    })
}

fn load_container<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<Vec<T>>> {
    match load_json_file::<BhContainer<T>>(path) {
        Ok(container) => Ok(Some(container.data)),
        Err(e) => {
            warn!("Skipping {}: {e}", path.display());
            Ok(None)
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Node registration
// ═══════════════════════════════════════════════════════════════

impl BhImportGraph {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            sid_to_name: HashMap::new(),
            name_to_sid: HashMap::new(),
            domain_nodes: Vec::new(),
        }
    }

    fn register_sid(&mut self, sid: &str, name: &str) {
        let upper = name.to_uppercase();
        self.sid_to_name
            .entry(sid.to_string())
            .or_insert_with(|| upper.clone());
        self.name_to_sid
            .entry(upper.clone())
            .or_insert_with(|| sid.to_string());
    }

    fn ensure_node(&mut self, sid: &str) -> Option<&AdNode> {
        if !self.nodes.contains_key(sid) {
            let name = self
                .sid_to_name
                .get(sid)
                .cloned()
                .unwrap_or_else(|| sid.to_string());
            let domain = name.split('@').nth(1).unwrap_or("UNKNOWN").to_string();
            let node = AdNode {
                name: name.clone(),
                node_type: NodeType::User,
                domain,
                distinguished_name: None,
                enabled: true,
                properties: HashMap::new(),
            };
            self.nodes.insert(sid.to_string(), node);
        }
        self.nodes.get(sid)
    }

    fn resolve_sid(&self, sid: &str) -> String {
        self.sid_to_name
            .get(sid)
            .cloned()
            .unwrap_or_else(|| sid.to_string())
    }

    fn add_edge(&mut self, src_sid: &str, tgt_sid: &str, edge: EdgeType) {
        self.edges
            .push((src_sid.to_string(), tgt_sid.to_string(), edge));
    }
}

// ═══════════════════════════════════════════════════════════════
//  Main import function
// ═══════════════════════════════════════════════════════════════

/// Import BloodHound JSON files from a directory into an AttackGraph.
///
/// Expects SharpHound v2 JSON files (users, computers, groups, domains, gpos, ous)
/// matching the pattern `*_users.json`, `*_computers.json`, etc.
pub fn import_bloodhound_dir(dir: &Path) -> Result<AttackGraph> {
    if !dir.is_dir() {
        return Err(OverthroneError::Custom(format!(
            "Not a directory: {}",
            dir.display()
        )));
    }

    let mut import = BhImportGraph::new();

    // Phase 1: Collect all JSON files
    let entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(e) => {
            return Err(OverthroneError::custom(format!(
                "IO error reading directory: {e}"
            )));
        }
    };

    // Phase 2: Load domains first (gives us domain SID -> name mapping)
    for entry in &entries {
        let fname = entry.file_name().unwrap_or_default().to_string_lossy();
        if fname.contains("domains") && fname.ends_with(".json") {
            info!("Loading domains from {}", fname);
            if let Ok(Some(domains)) = load_container::<BhDomain>(entry) {
                for d in &domains {
                    let name = extract_name(&d.properties, &d.object_identifier);
                    import.register_sid(&d.object_identifier, &name);
                    import.domain_nodes.push(d.object_identifier.clone());

                    import.nodes.insert(
                        d.object_identifier.clone(),
                        AdNode {
                            name: name.clone(),
                            node_type: NodeType::Domain,
                            domain: extract_domain(&d.properties),
                            distinguished_name: extract_dn(&d.properties),
                            enabled: true,
                            properties: d
                                .properties
                                .iter()
                                .map(|(k, v)| (k.clone(), format!("{v}")))
                                .collect(),
                        },
                    );

                    // Trust edges
                    for trust in &d.trusts {
                        if let Some(ref tgt_sid) = trust.target_domain_sid {
                            import.add_edge(&d.object_identifier, tgt_sid, EdgeType::TrustedBy);
                        }
                    }
                }
            }
        }
    }

    // Phase 3: Load users
    for entry in &entries {
        let fname = entry.file_name().unwrap_or_default().to_string_lossy();
        if fname.contains("users") && fname.ends_with(".json") {
            info!("Loading users from {}", fname);
            if let Ok(Some(users)) = load_container::<BhUser>(entry) {
                for u in &users {
                    let name = extract_name(&u.properties, &u.object_identifier);
                    import.register_sid(&u.object_identifier, &name);

                    let enabled = get_bool(&u.properties, "enabled");
                    let has_spn = get_bool(&u.properties, "hasspn");
                    let dont_req_preauth = get_bool(&u.properties, "dontreqpreauth");

                    import.nodes.insert(
                        u.object_identifier.clone(),
                        AdNode {
                            name: name.clone(),
                            node_type: NodeType::User,
                            domain: extract_domain(&u.properties),
                            distinguished_name: extract_dn(&u.properties),
                            enabled,
                            properties: u
                                .properties
                                .iter()
                                .map(|(k, v)| (k.clone(), format!("{v}")))
                                .collect(),
                        },
                    );

                    if has_spn {
                        for target in &u.spn_targets {
                            import.ensure_node(&target.object_identifier);
                            import.add_edge(
                                &u.object_identifier,
                                &target.object_identifier,
                                EdgeType::HasSpn,
                            );
                        }
                    }
                    if dont_req_preauth {
                        import.add_edge(
                            &u.object_identifier,
                            &u.object_identifier,
                            EdgeType::DontReqPreauth,
                        );
                    }

                    // MemberOf
                    for mo in &u.member_of {
                        import.ensure_node(&mo.object_identifier);
                        import.add_edge(
                            &u.object_identifier,
                            &mo.object_identifier,
                            EdgeType::MemberOf,
                        );
                    }

                    // ACEs
                    for ace in &u.aces {
                        if let Some(et) = bh_right_to_edge(&ace.right_name) {
                            import.ensure_node(&ace.principal_identifier);
                            import.add_edge(&ace.principal_identifier, &u.object_identifier, et);
                        }
                    }

                    // SIDHistory
                    for sh in &u.has_sid_history {
                        import.ensure_node(&sh.object_identifier);
                        import.add_edge(
                            &u.object_identifier,
                            &sh.object_identifier,
                            EdgeType::HasSidHistory,
                        );
                    }
                }
            }
        }
    }

    // Phase 4: Load computers
    for entry in &entries {
        let fname = entry.file_name().unwrap_or_default().to_string_lossy();
        if fname.contains("computers") && fname.ends_with(".json") {
            info!("Loading computers from {}", fname);
            if let Ok(Some(computers)) = load_container::<BhComputer>(entry) {
                for c in &computers {
                    let name = extract_name(&c.properties, &c.object_identifier);
                    import.register_sid(&c.object_identifier, &name);
                    let enabled = get_bool(&c.properties, "enabled");
                    let unconstrained = get_bool(&c.properties, "unconstraineddelegation");

                    let mut props: HashMap<String, String> = c
                        .properties
                        .iter()
                        .map(|(k, v)| (k.clone(), format!("{v}")))
                        .collect();
                    if unconstrained {
                        props.insert("unconstrained_delegation".to_string(), "true".to_string());
                    }

                    import.nodes.insert(
                        c.object_identifier.clone(),
                        AdNode {
                            name: name.clone(),
                            node_type: NodeType::Computer,
                            domain: extract_domain(&c.properties),
                            distinguished_name: extract_dn(&c.properties),
                            enabled,
                            properties: props,
                        },
                    );

                    // MemberOf
                    for mo in &c.member_of {
                        import.ensure_node(&mo.object_identifier);
                        import.add_edge(
                            &c.object_identifier,
                            &mo.object_identifier,
                            EdgeType::MemberOf,
                        );
                    }

                    // Sessions
                    for sess in &c.sessions {
                        import.ensure_node(&sess.object_identifier);
                        import.add_edge(
                            &sess.object_identifier,
                            &c.object_identifier,
                            EdgeType::HasSession,
                        );
                    }

                    // Local admins
                    for la in &c.local_admins {
                        import.ensure_node(&la.object_identifier);
                        import.add_edge(
                            &la.object_identifier,
                            &c.object_identifier,
                            EdgeType::AdminTo,
                        );
                    }

                    // AllowedToDelegate
                    for atd in &c.allowed_to_delegate {
                        import.ensure_node(&atd.object_identifier);
                        import.add_edge(
                            &c.object_identifier,
                            &atd.object_identifier,
                            EdgeType::AllowedToDelegate,
                        );
                    }

                    // AllowedToAct (RBCD)
                    for ata in &c.allowed_to_act {
                        import.ensure_node(&ata.object_identifier);
                        import.add_edge(
                            &ata.object_identifier,
                            &c.object_identifier,
                            EdgeType::AddAllowedToAct,
                        );
                    }

                    // ACEs
                    for ace in &c.aces {
                        if let Some(et) = bh_right_to_edge(&ace.right_name) {
                            import.ensure_node(&ace.principal_identifier);
                            import.add_edge(&ace.principal_identifier, &c.object_identifier, et);
                        }
                    }
                }
            }
        }
    }

    // Phase 5: Load groups
    for entry in &entries {
        let fname = entry.file_name().unwrap_or_default().to_string_lossy();
        if fname.contains("groups") && fname.ends_with(".json") {
            info!("Loading groups from {}", fname);
            if let Ok(Some(groups)) = load_container::<BhGroup>(entry) {
                for g in &groups {
                    let name = extract_name(&g.properties, &g.object_identifier);
                    import.register_sid(&g.object_identifier, &name);

                    import.nodes.insert(
                        g.object_identifier.clone(),
                        AdNode {
                            name: name.clone(),
                            node_type: NodeType::Group,
                            domain: extract_domain(&g.properties),
                            distinguished_name: extract_dn(&g.properties),
                            enabled: true,
                            properties: g
                                .properties
                                .iter()
                                .map(|(k, v)| (k.clone(), format!("{v}")))
                                .collect(),
                        },
                    );

                    // Group members
                    for member in &g.members {
                        if let Some(member_type) = &member.member_type {
                            let edge_type = match member_type.to_uppercase().as_str() {
                                "GROUP" => EdgeType::MemberOf,
                                "USER" => EdgeType::MemberOf,
                                "COMPUTER" => EdgeType::MemberOf,
                                _ => {
                                    import.ensure_node(&member.object_identifier);
                                    EdgeType::MemberOf
                                }
                            };
                            import.ensure_node(&member.object_identifier);
                            import.add_edge(
                                &member.object_identifier,
                                &g.object_identifier,
                                edge_type,
                            );
                        } else {
                            import.ensure_node(&member.object_identifier);
                            import.add_edge(
                                &member.object_identifier,
                                &g.object_identifier,
                                EdgeType::MemberOf,
                            );
                        }
                    }

                    // MemberOf (group is member of other groups)
                    for mo in &g.member_of {
                        import.ensure_node(&mo.object_identifier);
                        import.add_edge(
                            &g.object_identifier,
                            &mo.object_identifier,
                            EdgeType::MemberOf,
                        );
                    }

                    // ACEs
                    for ace in &g.aces {
                        if let Some(et) = bh_right_to_edge(&ace.right_name) {
                            import.ensure_node(&ace.principal_identifier);
                            import.add_edge(&ace.principal_identifier, &g.object_identifier, et);
                        }
                    }
                }
            }
        }
    }

    // Phase 6: Load GPOs and OUs
    for entry in &entries {
        let fname = entry.file_name().unwrap_or_default().to_string_lossy();
        if fname.contains("gpos") && fname.ends_with(".json") {
            info!("Loading GPOs from {}", fname);
            if let Ok(Some(gpos)) = load_container::<BhGpo>(entry) {
                for g in &gpos {
                    let name = extract_name(&g.properties, &g.object_identifier);
                    import.register_sid(&g.object_identifier, &name);
                    import.nodes.insert(
                        g.object_identifier.clone(),
                        AdNode {
                            name: name.clone(),
                            node_type: NodeType::Gpo,
                            domain: extract_domain(&g.properties),
                            distinguished_name: extract_dn(&g.properties),
                            enabled: true,
                            properties: g
                                .properties
                                .iter()
                                .map(|(k, v)| (k.clone(), format!("{v}")))
                                .collect(),
                        },
                    );
                    for ace in &g.aces {
                        if let Some(et) = bh_right_to_edge(&ace.right_name) {
                            import.ensure_node(&ace.principal_identifier);
                            import.add_edge(&ace.principal_identifier, &g.object_identifier, et);
                        }
                    }
                }
            }
        }
    }

    for entry in &entries {
        let fname = entry.file_name().unwrap_or_default().to_string_lossy();
        if fname.contains("ous") && fname.ends_with(".json") {
            info!("Loading OUs from {}", fname);
            if let Ok(Some(ous)) = load_container::<BhOu>(entry) {
                for o in &ous {
                    let name = extract_name(&o.properties, &o.object_identifier);
                    import.register_sid(&o.object_identifier, &name);
                    import.nodes.insert(
                        o.object_identifier.clone(),
                        AdNode {
                            name: name.clone(),
                            node_type: NodeType::Ou,
                            domain: extract_domain(&o.properties),
                            distinguished_name: extract_dn(&o.properties),
                            enabled: true,
                            properties: o
                                .properties
                                .iter()
                                .map(|(k, v)| (k.clone(), format!("{v}")))
                                .collect(),
                        },
                    );
                    // Child objects
                    for co in &o.child_objects {
                        import.ensure_node(&co.object_identifier);
                        import.add_edge(
                            &o.object_identifier,
                            &co.object_identifier,
                            EdgeType::Contains,
                        );
                    }
                    // GPO links
                    for link in &o.links {
                        import.ensure_node(&link.object_identifier);
                        import.add_edge(
                            &link.object_identifier,
                            &o.object_identifier,
                            EdgeType::GpoLink,
                        );
                    }
                    for ace in &o.aces {
                        if let Some(et) = bh_right_to_edge(&ace.right_name) {
                            import.ensure_node(&ace.principal_identifier);
                            import.add_edge(&ace.principal_identifier, &o.object_identifier, et);
                        }
                    }
                }
            }
        }
    }

    // ── Build the AttackGraph ──
    let mut graph = AttackGraph::new();

    // Add all nodes
    let mut sid_to_idx: HashMap<String, petgraph::graph::NodeIndex> = HashMap::new();
    for (sid, node) in &import.nodes {
        let idx = graph.add_node(node.clone());
        sid_to_idx.insert(sid.clone(), idx);
    }

    // Add all edges
    for (src_sid, tgt_sid, edge) in &import.edges {
        if let (Some(_src_idx), Some(_tgt_idx)) = (sid_to_idx.get(src_sid), sid_to_idx.get(tgt_sid))
        {
            let src_name = import.resolve_sid(src_sid);
            let src_domain = src_name.split('@').nth(1).unwrap_or("UNKNOWN").to_string();
            let tgt_name = import.resolve_sid(tgt_sid);
            let tgt_domain = tgt_name.split('@').nth(1).unwrap_or("UNKNOWN").to_string();
            graph.add_edge_by_name(&src_name, &src_domain, &tgt_name, &tgt_domain, edge.clone());
        }
    }

    info!(
        "BloodHound import complete: {} nodes, {} edges",
        sid_to_idx.len(),
        import.edges.len()
    );

    Ok(graph)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bh_right_to_edge_known() {
        assert!(bh_right_to_edge("GenericAll").is_some());
        assert!(bh_right_to_edge("ForceChangePassword").is_some());
        assert!(bh_right_to_edge("WriteOwner").is_some());
        assert!(bh_right_to_edge("AddMembers").is_some());
        assert!(bh_right_to_edge("ReadLapsPassword").is_some());
    }

    #[test]
    fn test_bh_right_to_edge_case_insensitive() {
        assert!(bh_right_to_edge("genericall").is_some());
        assert!(bh_right_to_edge("GENERICALL").is_some());
    }

    #[test]
    fn test_bh_right_to_edge_unknown_returns_none() {
        assert!(bh_right_to_edge("DoesNotExist").is_none());
        assert!(bh_right_to_edge("").is_none());
    }

    #[test]
    fn test_bh_right_to_edge_coverage() {
        let rights = [
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "Owns",
            "AllExtendedRights",
            "ForceChangePassword",
            "AddMembers",
            "AddSelf",
            "WriteSPN",
            "WriteKeyCredentialLink",
            "AddKeyCredentialLink",
            "WriteAllowedToDelegateTo",
            "AddAllowedToAct",
            "WriteAccountRestrictions",
            "GetChanges",
            "GetChangesAll",
            "Enroll",
            "ReadLapsPassword",
            "ReadGmsaPassword",
            "CanRDP",
            "CanPSRemote",
            "ExecuteDCOM",
            "SQLAdmin",
            "AllowedToDelegate",
            "Contains",
            "GpLink",
            "TrustedBy",
            "HasSidHistory",
        ];
        for right in &rights {
            assert!(
                bh_right_to_edge(right).is_some(),
                "Missing mapping: {right}"
            );
        }
    }

    #[test]
    fn test_bh_right_to_edge_underscore_variants() {
        assert!(bh_right_to_edge("GENERIC_WRITE").is_some());
        assert!(bh_right_to_edge("WRITE_DACL").is_some());
        assert!(bh_right_to_edge("ALL_EXTENDED_RIGHTS").is_some());
        assert!(bh_right_to_edge("FORCE_CHANGE_PASSWORD").is_some());
    }

    #[test]
    fn test_import_nonexistent_dir() {
        let result = import_bloodhound_dir(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_import_from_regular_file() {
        let result = import_bloodhound_dir(Path::new("Cargo.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_name_with_at_sign() {
        let mut props = HashMap::new();
        props.insert(
            "name".to_string(),
            serde_json::Value::String("user@DOMAIN.LOCAL".to_string()),
        );
        assert_eq!(extract_name(&props, "S-1-5-21-1"), "USER@DOMAIN.LOCAL");
    }

    #[test]
    fn test_extract_name_with_sam() {
        let mut props = HashMap::new();
        props.insert(
            "samaccountname".to_string(),
            serde_json::Value::String("jsmith".to_string()),
        );
        props.insert(
            "domain".to_string(),
            serde_json::Value::String("corp.local".to_string()),
        );
        assert_eq!(extract_name(&props, "S-1-5-21-1"), "JSMITH@CORP.LOCAL");
    }

    #[test]
    fn test_extract_name_fallback_to_sid() {
        let props = HashMap::new();
        let result = extract_name(&props, "S-1-5-21-1000");
        assert_eq!(result, "S-1-5-21-1000");
    }

    #[test]
    fn test_extract_dn_default() {
        let props = HashMap::new();
        assert_eq!(extract_domain(&props), "UNKNOWN");
    }
}
