//! MITRE ATT&CK mapper — Maps engagement findings to MITRE ATT&CK
//! techniques, tactics, and provides CVSS scoring helpers.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════
// MITRE ATT&CK Mapping
// ═══════════════════════════════════════════════════════════

/// A single MITRE ATT&CK technique mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub sub_technique_id: Option<String>,
    pub url: String,
}

impl MitreMapping {
    pub fn new(
        technique_id: &str,
        technique_name: &str,
        tactic: &str,
        sub_id: Option<&str>,
    ) -> Self {
        let full_id = match sub_id {
            Some(s) => format!("{}/{}", technique_id, s),
            None => technique_id.to_string(),
        };
        Self {
            technique_id: technique_id.to_string(),
            technique_name: technique_name.to_string(),
            tactic: tactic.to_string(),
            sub_technique_id: sub_id.map(String::from),
            url: format!("https://attack.mitre.org/techniques/{}/", full_id),
        }
    }
}

impl std::fmt::Display for MitreMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.sub_technique_id {
            Some(sub) => write!(
                f,
                "{}/{} — {} ({})",
                self.technique_id, sub, self.technique_name, self.tactic
            ),
            None => write!(
                f,
                "{} — {} ({})",
                self.technique_id, self.technique_name, self.tactic
            ),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Technique Database
// ═══════════════════════════════════════════════════════════

/// Map an attack type to its MITRE ATT&CK techniques
pub fn map_technique(attack_type: &str) -> Vec<MitreMapping> {
    match attack_type {
        "kerberoast" => vec![
            MitreMapping::new(
                "T1558",
                "Steal or Forge Kerberos Tickets",
                "Credential Access",
                Some("003"),
            ),
            MitreMapping::new("T1110", "Brute Force", "Credential Access", Some("002")),
        ],

        "asrep_roast" => vec![MitreMapping::new(
            "T1558",
            "Steal or Forge Kerberos Tickets",
            "Credential Access",
            Some("004"),
        )],

        "credential_access" => vec![
            MitreMapping::new("T1003", "OS Credential Dumping", "Credential Access", None),
            MitreMapping::new("T1110", "Brute Force", "Credential Access", None),
        ],

        "password_spray" => vec![MitreMapping::new(
            "T1110",
            "Brute Force",
            "Credential Access",
            Some("003"),
        )],

        "lateral_movement" => vec![
            MitreMapping::new("T1021", "Remote Services", "Lateral Movement", Some("002")),
            MitreMapping::new("T1570", "Lateral Tool Transfer", "Lateral Movement", None),
            MitreMapping::new("T1569", "System Services", "Execution", Some("002")),
        ],

        "psexec" | "smbexec" => vec![
            MitreMapping::new("T1021", "Remote Services", "Lateral Movement", Some("002")),
            MitreMapping::new("T1569", "System Services", "Execution", Some("002")),
            MitreMapping::new(
                "T1543",
                "Create or Modify System Process",
                "Persistence",
                Some("003"),
            ),
        ],

        "wmiexec" => vec![MitreMapping::new(
            "T1047",
            "Windows Management Instrumentation",
            "Execution",
            None,
        )],

        "winrm" => vec![MitreMapping::new(
            "T1021",
            "Remote Services",
            "Lateral Movement",
            Some("006"),
        )],

        "constrained_delegation" | "unconstrained_delegation" => vec![
            MitreMapping::new(
                "T1550",
                "Use Alternate Authentication Material",
                "Defense Evasion",
                Some("003"),
            ),
            MitreMapping::new(
                "T1558",
                "Steal or Forge Kerberos Tickets",
                "Credential Access",
                None,
            ),
        ],

        "dcsync" => vec![MitreMapping::new(
            "T1003",
            "OS Credential Dumping",
            "Credential Access",
            Some("006"),
        )],

        "sam_dump" => vec![MitreMapping::new(
            "T1003",
            "OS Credential Dumping",
            "Credential Access",
            Some("002"),
        )],

        "lsa_dump" => vec![MitreMapping::new(
            "T1003",
            "OS Credential Dumping",
            "Credential Access",
            Some("004"),
        )],

        "ntds_dump" => vec![MitreMapping::new(
            "T1003",
            "OS Credential Dumping",
            "Credential Access",
            Some("003"),
        )],

        "golden_ticket" => vec![MitreMapping::new(
            "T1558",
            "Steal or Forge Kerberos Tickets",
            "Credential Access",
            Some("001"),
        )],

        "silver_ticket" => vec![MitreMapping::new(
            "T1558",
            "Steal or Forge Kerberos Tickets",
            "Credential Access",
            Some("002"),
        )],

        "domain_admin" => vec![
            MitreMapping::new("T1078", "Valid Accounts", "Defense Evasion", Some("002")),
            MitreMapping::new(
                "T1484",
                "Domain Policy Modification",
                "Defense Evasion",
                None,
            ),
        ],

        "admin_access" => vec![
            MitreMapping::new("T1021", "Remote Services", "Lateral Movement", Some("002")),
            MitreMapping::new(
                "T1078",
                "Valid Accounts",
                "Privilege Escalation",
                Some("002"),
            ),
        ],

        "credential_exposure" => vec![
            MitreMapping::new("T1003", "OS Credential Dumping", "Credential Access", None),
            MitreMapping::new("T1552", "Unsecured Credentials", "Credential Access", None),
        ],

        "coercion" => vec![MitreMapping::new(
            "T1187",
            "Forced Authentication",
            "Credential Access",
            None,
        )],

        "rbcd" => vec![
            MitreMapping::new(
                "T1550",
                "Use Alternate Authentication Material",
                "Defense Evasion",
                Some("003"),
            ),
            MitreMapping::new("T1098", "Account Manipulation", "Persistence", None),
        ],

        _ => vec![],
    }
}

/// Get all unique tactics from a set of mappings
pub fn extract_tactics(mappings: &[MitreMapping]) -> Vec<String> {
    let mut tactics: Vec<String> = mappings.iter().map(|m| m.tactic.clone()).collect();
    tactics.sort();
    tactics.dedup();
    tactics
}

/// Build a MITRE ATT&CK matrix summary from all findings
pub fn build_attack_matrix(
    findings: &[super::session::Finding],
) -> Vec<(String, Vec<MitreMapping>)> {
    let mut by_tactic: std::collections::HashMap<String, Vec<MitreMapping>> =
        std::collections::HashMap::new();

    for finding in findings {
        for mapping in &finding.mitre {
            by_tactic
                .entry(mapping.tactic.clone())
                .or_default()
                .push(mapping.clone());
        }
    }

    // Deduplicate within each tactic
    for techniques in by_tactic.values_mut() {
        techniques.sort_by_key(|a| (a.technique_id.clone(), a.sub_technique_id.clone()));
        techniques.dedup_by(|a, b| {
            a.technique_id == b.technique_id && a.sub_technique_id == b.sub_technique_id
        });
    }

    // Order by kill chain
    let tactic_order = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Exfiltration",
        "Command and Control",
        "Impact",
    ];

    let mut result: Vec<(String, Vec<MitreMapping>)> = Vec::new();
    for tactic in &tactic_order {
        if let Some(techniques) = by_tactic.remove(*tactic) {
            result.push((tactic.to_string(), techniques));
        }
    }
    // Append any remaining
    for (tactic, techniques) in by_tactic {
        result.push((tactic, techniques));
    }
    result
}
