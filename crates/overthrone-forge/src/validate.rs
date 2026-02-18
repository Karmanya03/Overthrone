//! Input validation helpers for the forge pipeline.
//!
//! Validates SIDs, hashes, SPNs, domain names, and other inputs
//! before they reach the crypto/ASN.1 layer to give clear errors.

use overthrone_core::error::{OverthroneError, Result};
use tracing::debug;

/// Validate a Windows SID string format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
pub fn validate_sid_format(sid: &str) -> Result<()> {
    if !sid.starts_with("S-") && !sid.starts_with("s-") {
        return Err(OverthroneError::TicketForge(format!(
            "Invalid SID '{}': must start with 'S-'", sid
        )));
    }

    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 4 {
        return Err(OverthroneError::TicketForge(format!(
            "Invalid SID '{}': expected at least S-R-A-SubAuth, got {} parts",
            sid,
            parts.len()
        )));
    }

    // Validate revision (parts[1])
    let revision: u8 = parts[1].parse().map_err(|_| {
        OverthroneError::TicketForge(format!(
            "Invalid SID revision '{}': must be a number (usually 1)",
            parts[1]
        ))
    })?;
    if revision != 1 {
        return Err(OverthroneError::TicketForge(format!(
            "Unusual SID revision {}: expected 1", revision
        )));
    }

    // Validate authority (parts[2])
    let _authority: u64 = parts[2].parse().map_err(|_| {
        OverthroneError::TicketForge(format!(
            "Invalid SID authority '{}': must be a number (usually 5)",
            parts[2]
        ))
    })?;

    // Validate sub-authorities (parts[3..])
    for (i, sub) in parts[3..].iter().enumerate() {
        let _val: u32 = sub.parse().map_err(|_| {
            OverthroneError::TicketForge(format!(
                "Invalid SID sub-authority [{}] '{}': must be a 32-bit number",
                i, sub
            ))
        })?;
    }

    // Domain SIDs typically have 4 sub-authorities (21-X-Y-Z)
    if parts.len() < 7 {
        debug!(
            "SID '{}' has only {} sub-authorities (domain SIDs usually have 4: 21-X-Y-Z)",
            sid,
            parts.len() - 3
        );
    }

    Ok(())
}

/// Validate a hex-encoded hash string (NT hash = 32 chars, AES256 = 64 chars).
pub fn validate_hash_format(hash: &str, label: &str) -> Result<()> {
    let clean = hash.trim();

    if clean.is_empty() {
        return Err(OverthroneError::TicketForge(format!(
            "{} hash cannot be empty", label
        )));
    }

    // Must be valid hex
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OverthroneError::TicketForge(format!(
            "Invalid {} hash: contains non-hex characters", label
        )));
    }

    match clean.len() {
        32 => {
            debug!("{} hash: 16 bytes (RC4/NTLM)", label);
            Ok(())
        }
        64 => {
            debug!("{} hash: 32 bytes (AES256)", label);
            Ok(())
        }
        other => Err(OverthroneError::TicketForge(format!(
            "Invalid {} hash length: expected 32 (RC4) or 64 (AES256) hex chars, got {}",
            label, other
        ))),
    }
}

/// Validate an SPN format: "service/host" or "service/host.domain.com".
pub fn validate_spn_format(spn: &str) -> Result<()> {
    if spn.is_empty() {
        return Err(OverthroneError::TicketForge(
            "SPN cannot be empty".into()
        ));
    }

    let parts: Vec<&str> = spn.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(OverthroneError::TicketForge(format!(
            "Invalid SPN '{}': expected 'service/host' format", spn
        )));
    }

    let service = parts[0];
    let host = parts[1];

    if service.is_empty() {
        return Err(OverthroneError::TicketForge(format!(
            "Invalid SPN '{}': service class cannot be empty", spn
        )));
    }

    if host.is_empty() {
        return Err(OverthroneError::TicketForge(format!(
            "Invalid SPN '{}': hostname cannot be empty", spn
        )));
    }

    // Common service classes
    let known_services = [
        "HTTP", "CIFS", "HOST", "LDAP", "MSSQLSvc", "DNS", "TERMSRV",
        "WSMAN", "exchangeMDB", "exchangeRFR", "exchangeAB", "FTP",
        "RestrictedKrbHost", "GC", "IMAP", "POP", "SMTP", "MAPI",
        "http", "cifs", "host", "ldap", "mssqlsvc", "dns", "termsrv",
        "wsman",
    ];

    if !known_services.iter().any(|&s| service.eq_ignore_ascii_case(s)) {
        debug!(
            "SPN service class '{}' is not in the common set — may be custom",
            service
        );
    }

    Ok(())
}

/// Validate a domain name (FQDN or NetBIOS).
pub fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(OverthroneError::TicketForge(
            "Domain name cannot be empty".into()
        ));
    }

    if domain.len() > 255 {
        return Err(OverthroneError::TicketForge(format!(
            "Domain name too long: {} chars (max 255)", domain.len()
        )));
    }

    // Must not contain invalid characters
    let invalid_chars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|', ' '];
    for ch in invalid_chars {
        if domain.contains(ch) {
            return Err(OverthroneError::TicketForge(format!(
                "Domain name '{}' contains invalid character '{}'", domain, ch
            )));
        }
    }

    Ok(())
}

/// Validate that the user RID is within a reasonable range.
pub fn validate_rid(rid: u32) -> Result<()> {
    // RIDs below 1000 are typically built-in accounts
    // 500 = Administrator, 501 = Guest, 502 = krbtgt, 512+ = groups
    // Custom users start at 1000+
    if rid == 0 {
        return Err(OverthroneError::TicketForge(
            "User RID cannot be 0".into()
        ));
    }

    if rid > 0x3FFFFFFF {
        return Err(OverthroneError::TicketForge(format!(
            "User RID {} exceeds maximum (0x3FFFFFFF)", rid
        )));
    }

    debug!("RID {}: {}", rid, match rid {
        500 => "Administrator (built-in)",
        501 => "Guest",
        502 => "krbtgt",
        512 => "Domain Admins (group)",
        513 => "Domain Users (group)",
        514 => "Domain Guests (group)",
        515 => "Domain Computers (group)",
        516 => "Domain Controllers (group)",
        518 => "Schema Admins (group)",
        519 => "Enterprise Admins (group)",
        520 => "Group Policy Creator Owners (group)",
        1000.. => "Custom account",
        _ => "Well-known RID",
    });

    Ok(())
}

/// Validate group RIDs list.
pub fn validate_group_rids(rids: &[u32]) -> Result<()> {
    for &rid in rids {
        validate_rid(rid)?;
    }

    // Warn if Domain Users (513) is not in the list — tickets without it look suspicious
    if !rids.is_empty() && !rids.contains(&513) {
        debug!(
            "Group RIDs don't include 513 (Domain Users) — ticket may look suspicious to detections"
        );
    }

    Ok(())
}

/// Validate a list of extra SID strings.
pub fn validate_extra_sids(sids: &[String]) -> Result<()> {
    for sid in sids {
        validate_sid_format(sid)?;
    }
    Ok(())
}

/// Full validation of a ForgeConfig before execution.
pub fn validate_forge_config(config: &crate::runner::ForgeConfig) -> Result<()> {
    validate_domain(&config.domain)?;
    validate_rid(config.user_rid)?;
    validate_group_rids(&config.group_rids)?;
    validate_extra_sids(&config.extra_sids)?;

    if let Some(ref sid) = config.domain_sid {
        validate_sid_format(sid)?;
    }

    if let Some(ref hash) = config.krbtgt_hash {
        validate_hash_format(hash, "krbtgt")?;
    }

    if let Some(ref aes) = config.krbtgt_aes256 {
        validate_hash_format(aes, "krbtgt-aes256")?;
    }

    if let Some(ref hash) = config.service_hash {
        validate_hash_format(hash, "service")?;
    }

    if let Some(ref nt) = config.nt_hash {
        validate_hash_format(nt, "nt")?;
    }

    // Action-specific validation
    match &config.action {
        crate::runner::ForgeAction::GoldenTicket
        | crate::runner::ForgeAction::DiamondTicket
        | crate::runner::ForgeAction::InterRealmTgt { .. } => {
            if config.krbtgt_hash.is_none() && config.krbtgt_aes256.is_none() {
                return Err(OverthroneError::TicketForge(
                    "krbtgt hash or AES key required for this action".into()
                ));
            }
            if config.domain_sid.is_none() {
                return Err(OverthroneError::TicketForge(
                    "Domain SID required for this action".into()
                ));
            }
        }
        crate::runner::ForgeAction::SilverTicket { target_spn } => {
            validate_spn_format(target_spn)?;
            if config.service_hash.is_none() {
                return Err(OverthroneError::TicketForge(
                    "Service account hash required for Silver Ticket".into()
                ));
            }
            if config.domain_sid.is_none() {
                return Err(OverthroneError::TicketForge(
                    "Domain SID required for Silver Ticket".into()
                ));
            }
        }
        crate::runner::ForgeAction::SkeletonKey
        | crate::runner::ForgeAction::DsrmBackdoor => {
            if config.password.is_none() && config.nt_hash.is_none() {
                return Err(OverthroneError::TicketForge(
                    "Credentials required for persistence attacks".into()
                ));
            }
        }
        crate::runner::ForgeAction::DcSyncUser { .. } => {
            if config.password.is_none() && config.nt_hash.is_none() {
                return Err(OverthroneError::TicketForge(
                    "Credentials required for DCSync".into()
                ));
            }
        }
        crate::runner::ForgeAction::AclBackdoor { target_dn, trustee } => {
            if target_dn.is_empty() {
                return Err(OverthroneError::TicketForge(
                    "Target DN cannot be empty for ACL backdoor".into()
                ));
            }
            if trustee.is_empty() {
                return Err(OverthroneError::TicketForge(
                    "Trustee cannot be empty for ACL backdoor".into()
                ));
            }
        }
    }

    debug!("ForgeConfig validation passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_sid() {
        assert!(validate_sid_format("S-1-5-21-3623811015-3361044348-30300820").is_ok());
        assert!(validate_sid_format("S-1-5-21-1234567890-1234567890-1234567890").is_ok());
    }

    #[test]
    fn test_invalid_sid() {
        assert!(validate_sid_format("").is_err());
        assert!(validate_sid_format("not-a-sid").is_err());
        assert!(validate_sid_format("S-2-5-21-123").is_err()); // bad revision
        assert!(validate_sid_format("S-1-5").is_err());         // too short
    }

    #[test]
    fn test_valid_hash() {
        // RC4 (32 hex = 16 bytes)
        assert!(validate_hash_format("aad3b435b51404eeaad3b435b51404ee", "test").is_ok());
        // AES256 (64 hex = 32 bytes)
        assert!(validate_hash_format(
            &"ab".repeat(32), "test"
        ).is_ok());
    }

    #[test]
    fn test_invalid_hash() {
        assert!(validate_hash_format("", "test").is_err());
        assert!(validate_hash_format("tooshort", "test").is_err());
        assert!(validate_hash_format("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "test").is_err());
    }

    #[test]
    fn test_valid_spn() {
        assert!(validate_spn_format("CIFS/dc01.corp.local").is_ok());
        assert!(validate_spn_format("HTTP/webapp").is_ok());
        assert!(validate_spn_format("MSSQLSvc/sql01.corp.local:1433").is_ok());
    }

    #[test]
    fn test_invalid_spn() {
        assert!(validate_spn_format("").is_err());
        assert!(validate_spn_format("noslash").is_err());
        assert!(validate_spn_format("/noservice").is_err());
        assert!(validate_spn_format("CIFS/").is_err());
    }

    #[test]
    fn test_rid_validation() {
        assert!(validate_rid(500).is_ok());
        assert!(validate_rid(1001).is_ok());
        assert!(validate_rid(0).is_err());
    }

    #[test]
    fn test_domain_validation() {
        assert!(validate_domain("corp.local").is_ok());
        assert!(validate_domain("CONTOSO").is_ok());
        assert!(validate_domain("").is_err());
        assert!(validate_domain("bad domain").is_err());
    }
}
