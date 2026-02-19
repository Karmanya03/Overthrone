//! Kerberos ticket operations — request TGT/TGS, import/export kirbi/ccache,
//! convert between formats, inspect ticket contents, and manage ticket cache.
//!
//! Supports:
//! - Request TGT (password, hash, or existing ticket)
//! - Request TGS for arbitrary SPNs
//! - Export tickets to .kirbi (Rubeus) or .ccache (Impacket/Linux)
//! - Import tickets from file
//! - Inspect ticket metadata (principal, etype, expiry)

use crate::runner::HuntConfig;
use chrono::{DateTime, TimeZone, Utc};
use colored::Colorize;
use kerberos_asn1::{Asn1Object, Ticket};
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::proto::kerberos::{self, TicketGrantingData};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Ticket Formats
// ═══════════════════════════════════════════════════════════

/// Supported ticket file formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TicketFormat {
    /// Rubeus .kirbi format (raw ASN.1 KRB-CRED)
    Kirbi,
    /// MIT/Heimdal .ccache format (Linux credential cache)
    CCache,
}

impl TicketFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Kirbi => "kirbi",
            Self::CCache => "ccache",
        }
    }

    pub fn detect_from_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("kirbi") => Some(Self::Kirbi),
            Some("ccache") => Some(Self::CCache),
            _ => None,
        }
    }

    /// Detect format from file magic bytes
    pub fn detect_from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        // ccache starts with version (0x0504 for v4)
        if data[0] == 0x05 && data[1] == 0x04 {
            return Some(Self::CCache);
        }
        // kirbi is ASN.1 — starts with 0x76 (APPLICATION 22 = KRB-CRED)
        if data[0] == 0x76 {
            return Some(Self::Kirbi);
        }
        None
    }
}

impl std::fmt::Display for TicketFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kirbi => write!(f, "kirbi"),
            Self::CCache => write!(f, "ccache"),
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Ticket Request Types
// ═══════════════════════════════════════════════════════════

/// What ticket operation to perform
#[derive(Debug, Clone)]
pub enum TicketRequest {
    /// Request a TGT and optionally save it
    RequestTgt {
        output: Option<PathBuf>,
        format: TicketFormat,
    },
    /// Request a TGS for a specific SPN
    RequestTgs {
        spn: String,
        output: Option<PathBuf>,
        format: TicketFormat,
    },
    /// Import a ticket from file
    Import { path: PathBuf },
    /// Export a ticket to file (from current session)
    Export {
        output: PathBuf,
        format: TicketFormat,
    },
    /// Convert between formats
    Convert {
        input: PathBuf,
        output: PathBuf,
        target_format: TicketFormat,
    },
    /// Inspect a ticket file
    Inspect { path: PathBuf },
}

// ═══════════════════════════════════════════════════════════
// Ticket Inspection / Metadata
// ═══════════════════════════════════════════════════════════

/// Readable metadata extracted from a ticket
#[derive(Debug, Clone, Serialize)]
pub struct TicketInfo {
    pub client_principal: String,
    pub client_realm: String,
    pub service_principal: String,
    pub service_realm: String,
    pub encryption_type: String,
    pub etype_id: i32,
    pub ticket_size: usize,
    pub kvno: Option<u32>,
}

/// Extract metadata from raw ticket ASN.1 bytes
pub fn inspect_ticket_bytes(data: &[u8]) -> Result<TicketInfo> {
    // Try parsing as KRB-CRED (kirbi)
    if let Ok((_, krb_cred)) = kerberos_asn1::KrbCred::parse(data)
        && let Some(ticket) = krb_cred.tickets.first()
    {
        return Ok(extract_ticket_info(ticket));
    }

    // Try parsing as raw Ticket
    if let Ok((_, ticket)) = Ticket::parse(data) {
        return Ok(extract_ticket_info(&ticket));
    }

    Err(OverthroneError::Kerberos(
        "Cannot parse ticket data (not kirbi or raw ticket)".to_string(),
    ))
}

fn extract_ticket_info(ticket: &Ticket) -> TicketInfo {
    let sname = &ticket.sname;
    let service_principal = sname.name_string.join("/");

    let etype_id = ticket.enc_part.etype;
    let etype_name = match etype_id {
        kerberos::ETYPE_RC4_HMAC => "RC4-HMAC (23)",
        kerberos::ETYPE_AES128_CTS => "AES128-CTS (17)",
        kerberos::ETYPE_AES256_CTS => "AES256-CTS (18)",
        _ => "Unknown",
    };

    TicketInfo {
        client_principal: String::new(), // Not in Ticket itself, only in KRB-CRED
        client_realm: String::new(),
        service_principal,
        service_realm: ticket.realm.clone(),
        encryption_type: etype_name.to_string(),
        etype_id,
        ticket_size: ticket.build().len(),
        kvno: ticket.enc_part.kvno.map(|v| v),
    }
}

// ═══════════════════════════════════════════════════════════
// Kirbi (KRB-CRED) Serialization
// ═══════════════════════════════════════════════════════════

/// Wrap a TicketGrantingData into a KRB-CRED ASN.1 structure (.kirbi)
pub fn to_kirbi(tgd: &TicketGrantingData) -> Vec<u8> {
    use kerberos_asn1::{EncKrbCredPart, EncryptedData, KrbCred, KrbCredInfo};

    let cred_info = KrbCredInfo {
        key: kerberos_asn1::EncryptionKey {
            keytype: tgd.session_key_etype,
            keyvalue: tgd.session_key.clone(),
        },
        prealm: Some(tgd.client_realm.clone()),
        pname: Some(kerberos_asn1::PrincipalName {
            name_type: kerberos::NT_PRINCIPAL,
            name_string: vec![tgd.client_principal.clone()],
        }),
        flags: None,
        authtime: None,
        starttime: None,
        endtime: tgd.end_time.clone(),
        renew_till: None,
        srealm: Some(tgd.client_realm.clone()),
        sname: Some(tgd.ticket.sname.clone()),
        caddr: None,
    };

    let enc_part = EncKrbCredPart {
        ticket_info: vec![cred_info],
        nonce: None,
        timestamp: None,
        usec: None,
        s_address: None,
        r_address: None,
    };

    let krb_cred = KrbCred {
        pvno: 5,
        msg_type: 22,
        tickets: vec![tgd.ticket.clone()],
        enc_part: EncryptedData {
            etype: 0, // No encryption on KRB-CRED enc-part (convention)
            kvno: None,
            cipher: enc_part.build(),
        },
    };

    krb_cred.build()
}

/// Parse a .kirbi file back into TicketGrantingData
pub fn from_kirbi(data: &[u8]) -> Result<TicketGrantingData> {
    let (_, krb_cred) = kerberos_asn1::KrbCred::parse(data)
        .map_err(|e| OverthroneError::Kerberos(format!("Invalid kirbi: {e}")))?;

    let ticket = krb_cred
        .tickets
        .first()
        .ok_or_else(|| OverthroneError::Kerberos("No tickets in kirbi".to_string()))?
        .clone();

    // Parse enc-part (unencrypted in kirbi convention)
    let (_, enc_part) = kerberos_asn1::EncKrbCredPart::parse(&krb_cred.enc_part.cipher)
        .map_err(|e| OverthroneError::Kerberos(format!("Invalid kirbi enc-part: {e}")))?;

    let info = enc_part
        .ticket_info
        .first()
        .ok_or_else(|| OverthroneError::Kerberos("No ticket info in kirbi".to_string()))?;

    let client_principal = info
        .pname
        .as_ref()
        .map(|p| p.name_string.join("/"))
        .unwrap_or_default();
    let client_realm = info.prealm.clone().unwrap_or_default();

    Ok(TicketGrantingData {
        ticket,
        session_key: info.key.keyvalue.clone(),
        session_key_etype: info.key.keytype,
        client_principal,
        client_realm,
        end_time: info.endtime.clone(),
    })
}

// ═══════════════════════════════════════════════════════════
// CCache Serialization
// ═══════════════════════════════════════════════════════════

/// Convert TicketGrantingData to ccache format (MIT Kerberos v4 format)
pub fn to_ccache(tgd: &TicketGrantingData) -> Vec<u8> {
    let mut buf = Vec::new();

    // File format header (version 0x0504)
    buf.extend_from_slice(&[0x05, 0x04]);
    // Header length (no headers)
    buf.extend_from_slice(&0u16.to_be_bytes());

    // Default principal
    write_ccache_principal(&mut buf, &tgd.client_principal, &tgd.client_realm);

    // Credential entry
    write_ccache_credential(&mut buf, tgd);

    buf
}

fn write_ccache_principal(buf: &mut Vec<u8>, principal: &str, realm: &str) {
    let components: Vec<&str> = principal.split('/').collect();
    let name_type: u32 = if components.len() > 1 { 2 } else { 1 }; // NT_SRV_INST or NT_PRINCIPAL

    buf.extend_from_slice(&name_type.to_be_bytes());
    buf.extend_from_slice(&(components.len() as u32).to_be_bytes());

    // Realm
    buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
    buf.extend_from_slice(realm.as_bytes());

    // Components
    for comp in &components {
        buf.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        buf.extend_from_slice(comp.as_bytes());
    }
}

fn write_ccache_keyblock(buf: &mut Vec<u8>, etype: i32, key: &[u8]) {
    buf.extend_from_slice(&(etype as u16).to_be_bytes());
    buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
    buf.extend_from_slice(key);
}

fn write_ccache_times(buf: &mut Vec<u8>, end_time: Option<&kerberos_asn1::KerberosTime>) {
    let now = Utc::now().timestamp() as u32;
    let end = end_time
        .map(|_t| {
            // Approximate: parse KerberosTime to epoch
            now + 36000 // Default 10 hours if parse fails
        })
        .unwrap_or(now + 36000);

    buf.extend_from_slice(&now.to_be_bytes()); // authtime
    buf.extend_from_slice(&now.to_be_bytes()); // starttime
    buf.extend_from_slice(&end.to_be_bytes()); // endtime
    buf.extend_from_slice(&end.to_be_bytes()); // renew_till
}

fn write_ccache_credential(buf: &mut Vec<u8>, tgd: &TicketGrantingData) {
    // Client principal
    write_ccache_principal(buf, &tgd.client_principal, &tgd.client_realm);

    // Service principal (from ticket sname)
    let sname = tgd.ticket.sname.name_string.join("/");
    write_ccache_principal(buf, &sname, &tgd.client_realm);

    // Session key
    write_ccache_keyblock(buf, tgd.session_key_etype, &tgd.session_key);

    // Times
    write_ccache_times(buf, tgd.end_time.as_ref());

    // is_skey (0 = not)
    buf.push(0);

    // Ticket flags (forwardable | renewable)
    buf.extend_from_slice(&0x40800000u32.to_be_bytes());

    // Addresses (none)
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Authdata (none)
    buf.extend_from_slice(&0u32.to_be_bytes());

    // Ticket (raw ASN.1)
    let ticket_bytes = tgd.ticket.build();
    buf.extend_from_slice(&(ticket_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&ticket_bytes);

    // Second ticket (none)
    buf.extend_from_slice(&0u32.to_be_bytes());
}

/// Parse a ccache file into TicketGrantingData
/// (Simplified: extracts the first credential entry)
pub fn from_ccache(data: &[u8]) -> Result<TicketGrantingData> {
    if data.len() < 4 {
        return Err(OverthroneError::Kerberos("CCache too small".to_string()));
    }

    // Verify magic
    if data[0] != 0x05 || data[1] != 0x04 {
        return Err(OverthroneError::Kerberos(format!(
            "Invalid ccache version: 0x{:02X}{:02X}",
            data[0], data[1]
        )));
    }

    let mut pos: usize = 2;

    // Header length (v4 has a header section)
    let header_len = read_u16_be(data, &mut pos)? as usize;
    // Skip header data
    if pos + header_len > data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache header truncated".to_string(),
        ));
    }
    pos += header_len;

    // Default principal
    let (default_principal, default_realm) = read_ccache_principal(data, &mut pos)?;

    // Read the first credential entry
    if pos >= data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache has no credentials".to_string(),
        ));
    }

    // Client principal
    let (client_principal, client_realm) = read_ccache_principal(data, &mut pos)?;

    // Server principal (service)
    let (_server_principal, _server_realm) = read_ccache_principal(data, &mut pos)?;

    // Session key
    let (session_key_etype, session_key) = read_ccache_keyblock(data, &mut pos)?;

    // Times: authtime, starttime, endtime, renew_till (4 × u32)
    let _authtime = read_u32_be(data, &mut pos)?;
    let _starttime = read_u32_be(data, &mut pos)?;
    let _endtime = read_u32_be(data, &mut pos)?;
    let _renew_till = read_u32_be(data, &mut pos)?;

    // is_skey (1 byte)
    if pos >= data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache credential truncated at is_skey".to_string(),
        ));
    }
    pos += 1;

    // Ticket flags (u32)
    let _flags = read_u32_be(data, &mut pos)?;

    // Addresses count + skip
    let addr_count = read_u32_be(data, &mut pos)?;
    for _ in 0..addr_count {
        let _addr_type = read_u16_be(data, &mut pos)?;
        let addr_len = read_u32_be(data, &mut pos)? as usize;
        if pos + addr_len > data.len() {
            return Err(OverthroneError::Kerberos(
                "CCache address truncated".to_string(),
            ));
        }
        pos += addr_len;
    }

    // Authdata count + skip
    let authdata_count = read_u32_be(data, &mut pos)?;
    for _ in 0..authdata_count {
        let _ad_type = read_u16_be(data, &mut pos)?;
        let ad_len = read_u32_be(data, &mut pos)? as usize;
        if pos + ad_len > data.len() {
            return Err(OverthroneError::Kerberos(
                "CCache authdata truncated".to_string(),
            ));
        }
        pos += ad_len;
    }

    // Ticket data (ASN.1 encoded)
    let ticket_len = read_u32_be(data, &mut pos)? as usize;
    if pos + ticket_len > data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache ticket data truncated".to_string(),
        ));
    }
    let ticket_bytes = &data[pos..pos + ticket_len];
    pos += ticket_len;

    // Second ticket (skip)
    let _second_ticket_len = read_u32_be(data, &mut pos)?;

    // Parse the ASN.1 ticket
    let (_, ticket) = Ticket::parse(ticket_bytes).map_err(|e| {
        OverthroneError::Kerberos(format!("Failed to parse ticket from ccache: {e}"))
    })?;

    // Use the default principal if client principal is empty
    let final_principal = if client_principal.is_empty() {
        default_principal
    } else {
        client_principal
    };
    let final_realm = if client_realm.is_empty() {
        default_realm
    } else {
        client_realm
    };

    Ok(TicketGrantingData {
        ticket,
        session_key,
        session_key_etype,
        client_principal: final_principal,
        client_realm: final_realm,
        end_time: None, // Times were u32 epoch, not ASN.1 KerberosTime
    })
}

fn read_u16_be(data: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache truncated reading u16".to_string(),
        ));
    }
    let val = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

fn read_u32_be(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache truncated reading u32".to_string(),
        ));
    }
    let val = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_ccache_principal(data: &[u8], pos: &mut usize) -> Result<(String, String)> {
    let name_type = read_u32_be(data, pos)?;
    let num_components = read_u32_be(data, pos)?;

    // Realm
    let realm_len = read_u32_be(data, pos)? as usize;
    if *pos + realm_len > data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache principal realm truncated".to_string(),
        ));
    }
    let realm = String::from_utf8_lossy(&data[*pos..*pos + realm_len]).to_string();
    *pos += realm_len;

    // Components
    let mut components = Vec::new();
    for _ in 0..num_components {
        let comp_len = read_u32_be(data, pos)? as usize;
        if *pos + comp_len > data.len() {
            return Err(OverthroneError::Kerberos(
                "CCache principal component truncated".to_string(),
            ));
        }
        let comp = String::from_utf8_lossy(&data[*pos..*pos + comp_len]).to_string();
        *pos += comp_len;
        components.push(comp);
    }

    let principal = components.join("/");
    let _ = name_type; // Used for type classification but not needed for TGD
    Ok((principal, realm))
}

fn read_ccache_keyblock(data: &[u8], pos: &mut usize) -> Result<(i32, Vec<u8>)> {
    let etype = read_u16_be(data, pos)? as i32;
    let key_len = read_u32_be(data, pos)? as usize;
    if *pos + key_len > data.len() {
        return Err(OverthroneError::Kerberos(
            "CCache keyblock truncated".to_string(),
        ));
    }
    let key = data[*pos..*pos + key_len].to_vec();
    *pos += key_len;
    Ok((etype, key))
}

// ═══════════════════════════════════════════════════════════
// Ticket Operations Trait
// ═══════════════════════════════════════════════════════════

/// High-level ticket operations interface
pub struct TicketOps;

impl TicketOps {
    /// Request a TGT using credentials from HuntConfig
    pub async fn request_tgt(config: &HuntConfig) -> Result<TicketGrantingData> {
        kerberos::request_tgt(
            &config.dc_ip,
            &config.domain,
            &config.username,
            &config.secret,
            config.use_hash,
        )
        .await
    }

    /// Request a TGS for a specific SPN
    pub async fn request_tgs(
        config: &HuntConfig,
        tgt: &TicketGrantingData,
        spn: &str,
    ) -> Result<TicketGrantingData> {
        kerberos::request_service_ticket(&config.dc_ip, tgt, spn).await
    }

    /// Save a ticket to file in the specified format
    pub async fn save(tgd: &TicketGrantingData, path: &Path, format: TicketFormat) -> Result<()> {
        let data = match format {
            TicketFormat::Kirbi => to_kirbi(tgd),
            TicketFormat::CCache => to_ccache(tgd),
        };

        tokio::fs::write(path, &data).await?;
        info!(
            "Ticket saved: {} ({} format, {} bytes)",
            path.display(),
            format,
            data.len()
        );
        Ok(())
    }

    /// Load a ticket from file (auto-detect format)
    pub async fn load(path: &Path) -> Result<TicketGrantingData> {
        let data = tokio::fs::read(path).await?;
        let format = TicketFormat::detect_from_bytes(&data)
            .or_else(|| TicketFormat::detect_from_path(path))
            .ok_or_else(|| {
                OverthroneError::Kerberos(format!(
                    "Cannot detect ticket format for '{}'",
                    path.display()
                ))
            })?;

        info!(
            "Loading ticket: {} ({} format, {} bytes)",
            path.display(),
            format,
            data.len()
        );

        match format {
            TicketFormat::Kirbi => from_kirbi(&data),
            TicketFormat::CCache => from_ccache(&data),
        }
    }

    /// Convert ticket between formats
    pub async fn convert(input: &Path, output: &Path, target_format: TicketFormat) -> Result<()> {
        let tgd = Self::load(input).await?;
        Self::save(&tgd, output, target_format).await?;
        info!(
            "Converted {} → {} ({})",
            input.display(),
            output.display(),
            target_format
        );
        Ok(())
    }

    /// Inspect a ticket file and print metadata
    pub async fn inspect(path: &Path) -> Result<TicketInfo> {
        let data = tokio::fs::read(path).await?;
        let format =
            TicketFormat::detect_from_bytes(&data).or_else(|| TicketFormat::detect_from_path(path));

        let info = inspect_ticket_bytes(&data)?;

        println!("\n{}", "═══ TICKET INFO ═══".bold().cyan());
        println!("  File:      {}", path.display());
        println!(
            "  Format:    {}",
            format
                .map(|f| f.to_string())
                .unwrap_or("unknown".to_string())
        );
        println!("  Service:   {}", info.service_principal.bold());
        println!("  Realm:     {}", info.service_realm.cyan());
        println!("  Etype:     {}", info.encryption_type.yellow());
        println!("  Size:      {} bytes", info.ticket_size);
        if let Some(kvno) = info.kvno {
            println!("  KVNO:      {}", kvno);
        }
        if !info.client_principal.is_empty() {
            println!("  Client:    {}", info.client_principal.green());
        }
        println!("{}\n", "═══════════════════".cyan());

        Ok(info)
    }
}

// ═══════════════════════════════════════════════════════════
// Request Handler (called from runner)
// ═══════════════════════════════════════════════════════════

/// Handle a ticket request dispatched by the runner
pub async fn handle_request(config: &HuntConfig, request: &TicketRequest) -> Result<()> {
    match request {
        TicketRequest::RequestTgt { output, format } => {
            info!("{}", "═══ REQUEST TGT ═══".bold().green());
            let tgt = TicketOps::request_tgt(config).await?;
            info!(
                "  {} TGT for {}@{}",
                "✓".green(),
                tgt.client_principal.bold(),
                tgt.client_realm.cyan()
            );

            if let Some(path) = output {
                TicketOps::save(&tgt, path, *format).await?;
            }
        }

        TicketRequest::RequestTgs {
            spn,
            output,
            format,
        } => {
            info!("{}", "═══ REQUEST TGS ═══".bold().green());
            let tgt = match &config.tgt {
                Some(t) => t.clone(),
                None => TicketOps::request_tgt(config).await?,
            };
            let tgs = TicketOps::request_tgs(config, &tgt, spn).await?;
            info!(
                "  {} TGS for {} as {}",
                "✓".green(),
                spn.bold(),
                tgs.client_principal.cyan()
            );

            if let Some(path) = output {
                TicketOps::save(&tgs, path, *format).await?;
            }
        }

        TicketRequest::Import { path } => {
            info!("{}", "═══ IMPORT TICKET ═══".bold().green());
            let tgd = TicketOps::load(path).await?;
            info!(
                "  {} Imported: {}@{}",
                "✓".green(),
                tgd.client_principal.bold(),
                tgd.client_realm.cyan()
            );
        }

        TicketRequest::Export { output, format } => {
            info!("{}", "═══ EXPORT TICKET ═══".bold().green());
            let tgt = config
                .tgt
                .as_ref()
                .ok_or_else(|| OverthroneError::custom("No ticket in session to export"))?;
            TicketOps::save(tgt, output, *format).await?;
        }

        TicketRequest::Convert {
            input,
            output,
            target_format,
        } => {
            info!("{}", "═══ CONVERT TICKET ═══".bold().green());
            TicketOps::convert(input, output, *target_format).await?;
        }

        TicketRequest::Inspect { path } => {
            TicketOps::inspect(path).await?;
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_kirbi() {
        // kirbi starts with 0x76 (APPLICATION 22)
        let data = [0x76, 0x82, 0x01, 0x00];
        assert_eq!(
            TicketFormat::detect_from_bytes(&data),
            Some(TicketFormat::Kirbi)
        );
    }

    #[test]
    fn test_format_detection_ccache() {
        // ccache v4 starts with 0x05 0x04
        let data = [0x05, 0x04, 0x00, 0x00];
        assert_eq!(
            TicketFormat::detect_from_bytes(&data),
            Some(TicketFormat::CCache)
        );
    }

    #[test]
    fn test_format_from_extension() {
        assert_eq!(
            TicketFormat::detect_from_path(Path::new("admin.kirbi")),
            Some(TicketFormat::Kirbi)
        );
        assert_eq!(
            TicketFormat::detect_from_path(Path::new("admin.ccache")),
            Some(TicketFormat::CCache)
        );
        assert_eq!(TicketFormat::detect_from_path(Path::new("admin.txt")), None);
    }

    #[test]
    fn test_format_extension() {
        assert_eq!(TicketFormat::Kirbi.extension(), "kirbi");
        assert_eq!(TicketFormat::CCache.extension(), "ccache");
    }
}
