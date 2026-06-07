//! NTLMv1 Hash Detection and Downgrade Workflow
//!
//! Detects NTLMv1 hashes in collected credentials and provides
//! downgrade attack guidance for legacy domain environments.
//!
//! NTLMv1 uses DES-based LM hashes (56-bit keys) which are
//! significantly easier to crack than NTLMv2 (HMAC-MD5).
//!
//! This module:
//! 1. Identifies NTLMv1 vs NTLMv2 hashes in credential collections
//! 2. Provides cracking guidance (hashcat modes, expected time)
//! 3. Documents downgrade attack vectors for legacy compatibility

use serde::{Deserialize, Serialize};
use tracing::info;

/// NTLM hash type detection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NtlmHashType {
    /// NTLMv1 (legacy, DES-based LM hash)
    NtlmV1,
    /// NTLMv2 (modern, HMAC-MD5)
    NtlmV2,
    /// Unknown or mixed format
    Unknown,
}

/// NTLMv1 detection and analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtlmV1Analysis {
    /// Total hashes analyzed
    pub total_analyzed: usize,
    /// NTLMv1 hashes found
    pub ntlmv1_count: usize,
    /// NTLMv2 hashes found
    pub ntlmv2_count: usize,
    /// Unknown format hashes
    pub unknown_count: usize,
    /// List of NTLMv1 usernames
    pub ntlmv1_usernames: Vec<String>,
    /// Cracking difficulty assessment
    pub cracking_difficulty: CrackingDifficulty,
    /// Recommended hashcat command
    pub recommended_command: String,
    /// Downgrade attack feasibility
    pub downgrade_feasible: bool,
    /// Downgrade attack notes
    pub downgrade_notes: String,
}

/// Cracking difficulty assessment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrackingDifficulty {
    /// Trivial (LM hash, minutes on modern GPU)
    Trivial,
    /// Easy (NTLMv1 without LM, hours)
    Easy,
    /// Moderate (NTLMv2 with weak password, days)
    Moderate,
    /// Hard (NTLMv2 with strong password, weeks+)
    Hard,
}

impl std::fmt::Display for CrackingDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trivial => write!(f, "Trivial (LM hash, minutes)"),
            Self::Easy => write!(f, "Easy (NTLMv1, hours)"),
            Self::Moderate => write!(f, "Moderate (NTLMv2 weak, days)"),
            Self::Hard => write!(f, "Hard (NTLMv2 strong, weeks+)"),
        }
    }
}

/// Analyze a collection of hashes for NTLMv1 detection
pub fn analyze_ntlm_hashes(
    hashes: &[(String, String)], // (username, hash)
) -> NtlmV1Analysis {
    let mut analysis = NtlmV1Analysis {
        total_analyzed: hashes.len(),
        ntlmv1_count: 0,
        ntlmv2_count: 0,
        unknown_count: 0,
        ntlmv1_usernames: Vec::new(),
        cracking_difficulty: CrackingDifficulty::Hard,
        recommended_command: String::new(),
        downgrade_feasible: false,
        downgrade_notes: String::new(),
    };

    for (username, hash) in hashes {
        let hash_type = detect_ntlm_type(hash);

        match hash_type {
            NtlmHashType::NtlmV1 => {
                analysis.ntlmv1_count += 1;
                analysis.ntlmv1_usernames.push(username.clone());
            }
            NtlmHashType::NtlmV2 => {
                analysis.ntlmv2_count += 1;
            }
            NtlmHashType::Unknown => {
                analysis.unknown_count += 1;
            }
        }
    }

    // Determine cracking difficulty
    analysis.cracking_difficulty = if analysis.ntlmv1_count > 0 {
        CrackingDifficulty::Easy
    } else if analysis.ntlmv2_count > 0 {
        CrackingDifficulty::Moderate
    } else {
        CrackingDifficulty::Hard
    };

    // Generate recommended hashcat command
    analysis.recommended_command = if analysis.ntlmv1_count > 0 {
        "hashcat -m 5500 ntlmv1_hashes.txt wordlist.txt -r rules/best64.rule".to_string()
    } else if analysis.ntlmv2_count > 0 {
        "hashcat -m 5600 ntlmv2_hashes.txt wordlist.txt -r rules/best64.rule".to_string()
    } else {
        "No recognizable NTLM hashes found".to_string()
    };

    // Assess downgrade feasibility
    analysis.downgrade_feasible = analysis.ntlmv1_count > 0;
    analysis.downgrade_notes = if analysis.ntlmv1_count > 0 {
        format!(
            "Found {} NTLMv1 hash(es). These use DES-based LM hashing (56-bit keys) \
             and can be cracked in minutes to hours on modern GPUs. Consider targeting \
             these accounts first for fastest credential recovery.",
            analysis.ntlmv1_count
        )
    } else {
        "No NTLMv1 hashes detected. All hashes appear to be NTLMv2 (HMAC-MD5), \
         which requires dictionary/brute-force attacks. Consider using smart wordlists \
         from LDAP enumeration (organization names, usernames, seasonal patterns)."
            .to_string()
    };

    analysis
}

/// Detect NTLM hash type from hash string format
fn detect_ntlm_type(hash: &str) -> NtlmHashType {
    let parts: Vec<&str> = hash.split(':').collect();

    // NTLMv1 format: username::domain:lm_hash:nt_hash:challenge
    // Split gives: ["user", "", "DOMAIN", "lm_hash", "nt_hash", "challenge"]
    // LM hash is 16 chars, NT hash is 32 chars
    if parts.len() >= 6 {
        let lm_hash = parts[3];
        let nt_hash = parts[4];
        // NTLMv1 has short LM (16 chars) and NT (32 chars) hashes
        if lm_hash.len() == 16 && nt_hash.len() == 32 {
            return NtlmHashType::NtlmV1;
        }
    }

    // NTLMv2 format: username::domain:challenge:long_response:blob
    // Split gives: ["user", "", "DOMAIN", "challenge", "long_response", "blob"]
    // NTLMv2 response is typically 88+ chars (HMAC-MD5 + client challenge blob)
    if parts.len() >= 5 {
        let response = parts[4];
        // NTLMv2 has a long response (88+ chars typical)
        if response.len() >= 88 {
            return NtlmHashType::NtlmV2;
        }
    }

    // If it's just a 32-char hex string, it's likely a raw NTLM hash
    // (not NTLMv1 or NTLMv2, just the NT hash from DCSync/SAM)
    if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return NtlmHashType::Unknown;
    }

    NtlmHashType::Unknown
}

/// Generate downgrade attack guidance for legacy domains
pub fn generate_downgrade_guidance(
    dc_os_version: Option<&str>,
    functional_level: Option<u32>,
) -> DowngradeGuidance {
    let mut guidance = DowngradeGuidance {
        downgrade_feasible: false,
        recommended_technique: String::new(),
        prerequisites: Vec::new(),
        expected_success_rate: String::new(),
        opsec_risk: String::new(),
        mitigation_notes: String::new(),
    };

    // Check if downgrade is feasible based on DC OS and functional level
    let is_legacy = if let Some(os) = dc_os_version {
        os.to_lowercase().contains("2000")
            || os.to_lowercase().contains("2003")
            || os.to_lowercase().contains("2008")
    } else {
        false
    };

    let is_low_fl = functional_level.is_some_and(|fl| fl < 4);

    if is_legacy || is_low_fl {
        guidance.downgrade_feasible = true;
        guidance.recommended_technique = "NTLMv1 Downgrade via Responder".to_string();
        guidance.prerequisites = vec![
            "Network access to target segment (LLMNR/NBNS multicast)".to_string(),
            "Responder running on attacker machine".to_string(),
            "Target machines must support NTLMv1 (legacy Windows or misconfigured)".to_string(),
        ];
        guidance.expected_success_rate = "High on Windows 2000/2003/XP, low on Vista+".to_string();
        guidance.opsec_risk = "HIGH: Generates network noise, easily detectable by NDR/IDS".to_string();
        guidance.mitigation_notes = "Modern domains (2012+) enforce NTLMv2 via LmCompatibilityLevel=5. \
                                    Downgrade only works on legacy systems or when GPO misconfigurations exist."
            .to_string();
    } else {
        guidance.downgrade_feasible = false;
        guidance.recommended_technique = "Not feasible - modern domain enforces NTLMv2".to_string();
        guidance.prerequisites = vec![
            "NTLMv1 downgrade requires legacy DC or misconfigured GPO".to_string(),
            "Modern domains set LmCompatibilityLevel=5 (NTLMv2 only)".to_string(),
        ];
        guidance.expected_success_rate = "Very low on modern domains".to_string();
        guidance.opsec_risk = "N/A - downgrade not feasible".to_string();
        guidance.mitigation_notes = "Focus on NTLMv2 cracking with smart wordlists instead."
            .to_string();
    }

    guidance
}

/// Downgrade attack guidance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DowngradeGuidance {
    /// Whether downgrade is feasible
    pub downgrade_feasible: bool,
    /// Recommended technique
    pub recommended_technique: String,
    /// Prerequisites for attack
    pub prerequisites: Vec<String>,
    /// Expected success rate
    pub expected_success_rate: String,
    /// OPSEC risk level
    pub opsec_risk: String,
    /// Mitigation notes
    pub mitigation_notes: String,
}

/// Run full NTLMv1 detection and analysis workflow
pub async fn run_ntlmv1_workflow(
    hashes: &[(String, String)],
    dc_os_version: Option<&str>,
    functional_level: Option<u32>,
) -> NtlmV1WorkflowResult {
    info!("Starting NTLMv1 detection workflow...");

    // Step 1: Analyze hashes
    let analysis = analyze_ntlm_hashes(hashes);

    info!(
        "Found {} NTLMv1, {} NTLMv2, {} unknown",
        analysis.ntlmv1_count, analysis.ntlmv2_count, analysis.unknown_count
    );

    // Step 2: Generate downgrade guidance
    let downgrade_guidance = generate_downgrade_guidance(dc_os_version, functional_level);

    info!(
        "NTLMv1 downgrade feasible: {}",
        downgrade_guidance.downgrade_feasible
    );

    NtlmV1WorkflowResult {
        analysis,
        downgrade_guidance,
    }
}

/// Full NTLMv1 workflow result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtlmV1WorkflowResult {
    /// Hash analysis
    pub analysis: NtlmV1Analysis,
    /// Downgrade guidance
    pub downgrade_guidance: DowngradeGuidance,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ntlmv1_format() {
        // NTLMv1: user::DOMAIN:LM_hash(16):NT_hash(32):challenge(16)
        let hash = "user::DOMAIN:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:0102030405060708";
        assert_eq!(detect_ntlm_type(hash), NtlmHashType::NtlmV1);
    }

    #[test]
    fn test_detect_ntlmv2_format() {
        // NTLMv2: user::DOMAIN:challenge(16):NTLMv2_response(88+):blob
        let hash = "user::DOMAIN:1122334455667788:0102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162636465666768:1122334455667788";
        assert_eq!(detect_ntlm_type(hash), NtlmHashType::NtlmV2);
    }

    #[test]
    fn test_detect_raw_ntlm_hash() {
        // Raw NT hash (32 hex chars, no colons)
        let hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        assert_eq!(detect_ntlm_type(hash), NtlmHashType::Unknown);
    }

    #[test]
    fn test_analyze_mixed_hashes() {
        let hashes = vec![
            ("user1".to_string(), "user1::DOMAIN:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:0102030405060708".to_string()), // NTLMv1
            ("user2".to_string(), "user2::DOMAIN:1122334455667788:0102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162636465666768:1122334455667788".to_string()), // NTLMv2
            ("user3".to_string(), "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string()), // Raw NT
        ];

        let analysis = analyze_ntlm_hashes(&hashes);
        assert_eq!(analysis.total_analyzed, 3);
        assert_eq!(analysis.ntlmv1_count, 1);
        assert_eq!(analysis.ntlmv2_count, 1);
        assert_eq!(analysis.unknown_count, 1);
        assert_eq!(analysis.ntlmv1_usernames.len(), 1);
        assert_eq!(analysis.ntlmv1_usernames[0], "user1");
    }

    #[test]
    fn test_analyze_all_ntlmv1() {
        let hashes = vec![
            ("user1".to_string(), "user1::DOMAIN:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:0102030405060708".to_string()),
            ("user2".to_string(), "user2::DOMAIN:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:1122334455667788".to_string()),
        ];

        let analysis = analyze_ntlm_hashes(&hashes);
        assert_eq!(analysis.ntlmv1_count, 2);
        assert_eq!(analysis.cracking_difficulty, CrackingDifficulty::Easy);
        assert!(analysis.recommended_command.contains("-m 5500"));
    }

    #[test]
    fn test_downgrade_guidance_legacy_domain() {
        let guidance = generate_downgrade_guidance(Some("Windows Server 2003"), Some(2));
        assert!(guidance.downgrade_feasible);
        assert!(guidance.recommended_technique.contains("NTLMv1"));
        assert!(!guidance.prerequisites.is_empty());
    }

    #[test]
    fn test_downgrade_guidance_modern_domain() {
        let guidance = generate_downgrade_guidance(Some("Windows Server 2019"), Some(7));
        assert!(!guidance.downgrade_feasible);
        assert!(guidance.recommended_technique.contains("Not feasible"));
    }

    #[test]
    fn test_cracking_difficulty_display() {
        assert!(CrackingDifficulty::Trivial.to_string().contains("Trivial"));
        assert!(CrackingDifficulty::Easy.to_string().contains("Easy"));
        assert!(CrackingDifficulty::Moderate.to_string().contains("Moderate"));
        assert!(CrackingDifficulty::Hard.to_string().contains("Hard"));
    }
}
