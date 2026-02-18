//! Cleanup and opsec utilities for the forge pipeline.
//!
//! Provides functions to:
//! - Securely wipe forged tickets from disk
//! - Generate cleanup scripts for persistence mechanisms
//! - Remove traces from the local system (event logs, temp files)
//! - Estimate detection risk for each forge action

use overthrone_core::error::{OverthroneError, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::runner::{ForgeAction, ForgeResult, PersistenceResult};

// ═══════════════════════════════════════════════════════════
// Ticket File Cleanup
// ═══════════════════════════════════════════════════════════

/// Securely delete a forged ticket file by overwriting with random bytes before unlinking.
pub fn secure_delete_ticket(path: &str) -> Result<()> {
    let file_path = Path::new(path);
    if !file_path.exists() {
        debug!("[cleanup] File not found (already removed?): {}", path);
        return Ok(());
    }

    // Read file size
    let metadata = std::fs::metadata(file_path).map_err(|e| {
        OverthroneError::Custom(format!("Cannot stat '{}': {}", path, e))
    })?;
    let size = metadata.len() as usize;

    // Overwrite with random data (3 passes)
    for pass in 0..3 {
        let random_data: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
        std::fs::write(file_path, &random_data).map_err(|e| {
            OverthroneError::Custom(format!("Overwrite pass {} failed for '{}': {}", pass, path, e))
        })?;
        // Force flush to disk
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(file_path)
            .map_err(|e| OverthroneError::Custom(format!("Cannot open for sync: {e}")))?;
        file.sync_all().map_err(|e| {
            OverthroneError::Custom(format!("Sync failed: {e}"))
        })?;
    }

    // Zero-fill final pass
    let zeros = vec![0u8; size];
    std::fs::write(file_path, &zeros).map_err(|e| {
        OverthroneError::Custom(format!("Zero-fill failed: {e}"))
    })?;

    // Delete the file
    std::fs::remove_file(file_path).map_err(|e| {
        OverthroneError::Custom(format!("Cannot remove '{}': {}", path, e))
    })?;

    info!("[cleanup] Securely deleted: {} ({} bytes, 4 passes)", path, size);
    Ok(())
}

/// Clean up all .kirbi and .ccache files in a directory.
pub fn cleanup_ticket_directory(dir: &str) -> Result<usize> {
    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        return Err(OverthroneError::Custom(format!(
            "'{}' is not a directory", dir
        )));
    }

    let mut cleaned = 0;
    let extensions = ["kirbi", "ccache", "ticket"];

    for entry in std::fs::read_dir(dir_path).map_err(|e| {
        OverthroneError::Custom(format!("Cannot read dir '{}': {}", dir, e))
    })? {
        let entry = entry.map_err(|e| {
            OverthroneError::Custom(format!("Dir entry error: {e}"))
        })?;

        let path = entry.path();
        if let Some(ext) = path.extension()
            && extensions.iter().any(|&e| ext == e) {
                let path_str = path.to_string_lossy().to_string();
                secure_delete_ticket(&path_str)?;
                cleaned += 1;
            }
    }

    info!("[cleanup] Cleaned {} ticket files from {}", cleaned, dir);
    Ok(cleaned)
}

// ═══════════════════════════════════════════════════════════
// Persistence Cleanup Scripts
// ═══════════════════════════════════════════════════════════

/// Generate comprehensive cleanup instructions for a forge result.
pub fn generate_cleanup_plan(result: &ForgeResult) -> CleanupPlan {
    let mut steps = Vec::new();

    // Ticket file cleanup
    if let Some(ref ticket) = result.ticket_data {
        if let Some(ref path) = ticket.kirbi_path {
            steps.push(CleanupStep {
                order: 1,
                category: CleanupCategory::LocalFile,
                description: format!("Securely delete kirbi file: {}", path),
                command: Some(format!(
                    "# Rust: cleanup::secure_delete_ticket(\"{}\")\n\
                     # Or manual: shred -vfz -n 3 '{}'",
                    path, path
                )),
                risk_if_skipped: "Forged ticket on disk — forensic evidence".into(),
                automated: true,
            });
        }
        if let Some(ref path) = ticket.ccache_path {
            steps.push(CleanupStep {
                order: 2,
                category: CleanupCategory::LocalFile,
                description: format!("Securely delete ccache file: {}", path),
                command: Some(format!("shred -vfz -n 3 '{}'", path)),
                risk_if_skipped: "Credential cache on disk".into(),
                automated: true,
            });
        }
    }

    // Persistence-specific cleanup
    if let Some(ref persistence) = result.persistence_result
        && let Some(ref cmd) = persistence.cleanup_command {
            steps.push(CleanupStep {
                order: 10,
                category: CleanupCategory::RemotePersistence,
                description: format!("Remove {} from {}", persistence.mechanism, persistence.target),
                command: Some(cmd.clone()),
                risk_if_skipped: format!(
                    "Persistent backdoor remains: {}", persistence.mechanism
                ),
                automated: false,
            });
        }

    // Environment cleanup
    steps.push(CleanupStep {
        order: 20,
        category: CleanupCategory::Environment,
        description: "Clear Kerberos ticket cache".into(),
        command: Some(
            "# Linux:\nkdestroy -A\n\n# Windows:\nklist purge\n\n# macOS:\nkdestroy -A".into()
        ),
        risk_if_skipped: "Forged tickets remain in memory".into(),
        automated: true,
    });

    steps.push(CleanupStep {
        order: 21,
        category: CleanupCategory::Environment,
        description: "Clear shell history".into(),
        command: Some(
            "# Bash:\nhistory -c && history -w\n\
             # Zsh:\nfc -W /dev/null\n\
             # PowerShell:\nClear-History; Remove-Item (Get-PSReadLineOption).HistorySavePath -Force"
                .into()
        ),
        risk_if_skipped: "Command history contains hashes and targets".into(),
        automated: false,
    });

    steps.push(CleanupStep {
        order: 22,
        category: CleanupCategory::Environment,
        description: "Remove environment variables with credentials".into(),
        command: Some(
            "unset KRB5CCNAME\nunset NTLM_HASH\nunset KRBTGT_KEY".into()
        ),
        risk_if_skipped: "Credentials in environment variables".into(),
        automated: true,
    });

    CleanupPlan {
        action: result.action.clone(),
        target_domain: result.domain.clone(),
        steps,
    }
}

/// Execute automated cleanup steps from a plan.
pub fn execute_cleanup_plan(plan: &CleanupPlan) -> Result<CleanupReport> {
    info!("[cleanup] Executing cleanup plan for: {}", plan.action);

    let mut completed = Vec::new();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();

    for step in &plan.steps {
        if !step.automated {
            skipped.push(CleanupStepResult {
                step: step.description.clone(),
                status: StepStatus::Skipped,
                message: "Manual step — see command".into(),
            });
            continue;
        }

        match step.category {
            CleanupCategory::LocalFile => {
                // Extract file path from description and attempt deletion
                if let Some(ref cmd) = step.command
                    && cmd.contains("secure_delete_ticket") {
                        // Parse path from command
                        if let Some(path) = extract_path_from_cleanup_cmd(cmd) {
                            match secure_delete_ticket(&path) {
                                Ok(()) => {
                                    completed.push(CleanupStepResult {
                                        step: step.description.clone(),
                                        status: StepStatus::Completed,
                                        message: "File securely deleted".into(),
                                    });
                                }
                                Err(e) => {
                                    failed.push(CleanupStepResult {
                                        step: step.description.clone(),
                                        status: StepStatus::Failed,
                                        message: format!("Delete failed: {e}"),
                                    });
                                }
                            }
                        }
                    }
            }
            CleanupCategory::Environment => {
                // Clear KRB5CCNAME env var
                unsafe {
                    std::env::remove_var("KRB5CCNAME");
                    std::env::remove_var("NTLM_HASH");
                    std::env::remove_var("KRBTGT_KEY");
                }
                completed.push(CleanupStepResult {
                    step: step.description.clone(),
                    status: StepStatus::Completed,
                    message: "Environment cleaned".into(),
                });
            }
            CleanupCategory::RemotePersistence => {
                skipped.push(CleanupStepResult {
                    step: step.description.clone(),
                    status: StepStatus::Skipped,
                    message: "Remote persistence requires manual execution".into(),
                });
            }
        }
    }

    let total = completed.len() + failed.len() + skipped.len();
    info!(
        "[cleanup] Results: {}/{} completed, {} failed, {} skipped",
        completed.len(), total, failed.len(), skipped.len()
    );

    Ok(CleanupReport {
        action: plan.action.clone(),
        completed,
        failed,
        skipped,
    })
}

// ═══════════════════════════════════════════════════════════
// Detection Risk Assessment
// ═══════════════════════════════════════════════════════════

/// Estimate the detection risk for a given forge action.
pub fn assess_detection_risk(action: &ForgeAction) -> DetectionAssessment {
    match action {
        ForgeAction::GoldenTicket => DetectionAssessment {
            overall_risk: RiskLevel::Medium,
            description: "Golden Ticket has moderate detection risk".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "Event ID 4769".into(),
                    detail: "TGS request with forged TGT — no corresponding 4768 (AS-REQ)".into(),
                    severity: RiskLevel::High,
                },
                DetectionIndicator {
                    source: "Event ID 4624/4634".into(),
                    detail: "Logon events with unusual ticket properties (lifetime, groups)".into(),
                    severity: RiskLevel::Low,
                },
                DetectionIndicator {
                    source: "Ticket metadata".into(),
                    detail: "TGT with no corresponding AS-REQ in KDC logs".into(),
                    severity: RiskLevel::Medium,
                },
            ],
            mitigations: vec![
                "Use AES256 instead of RC4 to avoid etype-downgrade detection".into(),
                "Set realistic ticket lifetime (8-10 hours, not 10 years)".into(),
                "Include Domain Users (513) in group list".into(),
                "Use Diamond Ticket instead for better stealth".into(),
            ],
        },

        ForgeAction::SilverTicket { .. } => DetectionAssessment {
            overall_risk: RiskLevel::Low,
            description: "Silver Ticket is harder to detect — never touches the KDC".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "Service logs".into(),
                    detail: "Service ticket without corresponding TGS request to KDC".into(),
                    severity: RiskLevel::Medium,
                },
                DetectionIndicator {
                    source: "PAC validation".into(),
                    detail: "If service validates PAC with KDC (PAC_SERVER_CHECKSUM)".into(),
                    severity: RiskLevel::High,
                },
            ],
            mitigations: vec![
                "Target services that don't validate PAC with KDC".into(),
                "Use matching encryption type to the service account".into(),
            ],
        },

        ForgeAction::DiamondTicket => DetectionAssessment {
            overall_risk: RiskLevel::VeryLow,
            description: "Diamond Ticket is very stealthy — modifies a real TGT".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "PAC inspection".into(),
                    detail: "PAC contents don't match AD (requires deep PAC analysis)".into(),
                    severity: RiskLevel::Low,
                },
                DetectionIndicator {
                    source: "Event ID 4768".into(),
                    detail: "Legitimate AS-REQ exists, making it look normal".into(),
                    severity: RiskLevel::VeryLow,
                },
            ],
            mitigations: vec![
                "Already the stealthiest ticket forging technique".into(),
                "Use AES256 for the krbtgt key to match normal traffic".into(),
            ],
        },

        ForgeAction::InterRealmTgt { .. } => DetectionAssessment {
            overall_risk: RiskLevel::Medium,
            description: "Inter-realm TGT is moderate risk — cross-domain traffic is logged".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "Event ID 4769".into(),
                    detail: "Cross-realm TGS request with unusual SID history".into(),
                    severity: RiskLevel::Medium,
                },
            ],
            mitigations: vec![
                "SID filtering may block ExtraSIDs — check trust configuration".into(),
                "Use a trust key obtained through legitimate compromise".into(),
            ],
        },

        ForgeAction::SkeletonKey => DetectionAssessment {
            overall_risk: RiskLevel::High,
            description: "Skeleton Key patches LSASS — detectable by endpoint monitoring".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "EDR/AV".into(),
                    detail: "LSASS memory modification detected by most modern EDRs".into(),
                    severity: RiskLevel::Critical,
                },
                DetectionIndicator {
                    source: "Event ID 7045".into(),
                    detail: "New service installation for DLL injection".into(),
                    severity: RiskLevel::High,
                },
            ],
            mitigations: vec![
                "Ensure EDR exclusions or use kernel driver method".into(),
                "Skeleton Key doesn't survive reboot — use sparingly".into(),
            ],
        },

        ForgeAction::DsrmBackdoor => DetectionAssessment {
            overall_risk: RiskLevel::Medium,
            description: "DSRM backdoor modifies registry — logged by auditing".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "Event ID 4657".into(),
                    detail: "Registry value DsrmAdminLogonBehavior modified".into(),
                    severity: RiskLevel::High,
                },
                DetectionIndicator {
                    source: "Event ID 4624".into(),
                    detail: "Local account network logon on a DC is unusual".into(),
                    severity: RiskLevel::Medium,
                },
            ],
            mitigations: vec![
                "Use during maintenance windows when registry changes are expected".into(),
            ],
        },

        ForgeAction::DcSyncUser { .. } => DetectionAssessment {
            overall_risk: RiskLevel::Medium,
            description: "DCSync replication is logged — but looks like normal DC replication".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "Event ID 4662".into(),
                    detail: "Replicating Directory Changes All from non-DC source".into(),
                    severity: RiskLevel::High,
                },
            ],
            mitigations: vec![
                "Perform from a machine with a DC-like hostname".into(),
                "Limit to specific users rather than full domain dump".into(),
            ],
        },

        ForgeAction::AclBackdoor { .. } => DetectionAssessment {
            overall_risk: RiskLevel::Low,
            description: "ACL changes are rarely audited — very stealthy persistence".into(),
            indicators: vec![
                DetectionIndicator {
                    source: "Event ID 5136".into(),
                    detail: "nTSecurityDescriptor modification (if SACL auditing enabled)".into(),
                    severity: RiskLevel::Medium,
                },
                DetectionIndicator {
                    source: "ACL diff tools".into(),
                    detail: "BloodHound/ADACLScanner would find the extra ACE".into(),
                    severity: RiskLevel::Low,
                },
            ],
            mitigations: vec![
                "Use a low-profile trustee account (not obvious names)".into(),
                "ACL changes survive krbtgt rotations — very persistent".into(),
            ],
        },
    }
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanupPlan {
    pub action: String,
    pub target_domain: String,
    pub steps: Vec<CleanupStep>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanupStep {
    pub order: u32,
    pub category: CleanupCategory,
    pub description: String,
    pub command: Option<String>,
    pub risk_if_skipped: String,
    pub automated: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum CleanupCategory {
    LocalFile,
    Environment,
    RemotePersistence,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanupReport {
    pub action: String,
    pub completed: Vec<CleanupStepResult>,
    pub failed: Vec<CleanupStepResult>,
    pub skipped: Vec<CleanupStepResult>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanupStepResult {
    pub step: String,
    pub status: StepStatus,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum StepStatus {
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectionAssessment {
    pub overall_risk: RiskLevel,
    pub description: String,
    pub indicators: Vec<DetectionIndicator>,
    pub mitigations: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectionIndicator {
    pub source: String,
    pub detail: String,
    pub severity: RiskLevel,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, PartialOrd)]
pub enum RiskLevel {
    VeryLow,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VeryLow => write!(f, "VERY LOW"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

fn extract_path_from_cleanup_cmd(cmd: &str) -> Option<String> {
    // Parse: secure_delete_ticket("some/path.kirbi")
    if let Some(start) = cmd.find('"')
        && let Some(end) = cmd[start + 1..].find('"') {
            return Some(cmd[start + 1..start + 1 + end].to_string());
        }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_ordering() {
        assert!(RiskLevel::VeryLow < RiskLevel::Low);
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_extract_path() {
        let cmd = r#"secure_delete_ticket("golden_Admin_CORP_LOCAL.kirbi")"#;
        assert_eq!(
            extract_path_from_cleanup_cmd(cmd),
            Some("golden_Admin_CORP_LOCAL.kirbi".to_string())
        );
    }

    #[test]
    fn test_detection_assessment_golden() {
        let assessment = assess_detection_risk(&ForgeAction::GoldenTicket);
        assert_eq!(assessment.overall_risk, RiskLevel::Medium);
        assert!(!assessment.indicators.is_empty());
        assert!(!assessment.mitigations.is_empty());
    }

    #[test]
    fn test_detection_assessment_diamond() {
        let assessment = assess_detection_risk(&ForgeAction::DiamondTicket);
        assert_eq!(assessment.overall_risk, RiskLevel::VeryLow);
    }

    #[test]
    fn test_detection_assessment_skeleton() {
        let assessment = assess_detection_risk(&ForgeAction::SkeletonKey);
        assert_eq!(assessment.overall_risk, RiskLevel::High);
    }
}
