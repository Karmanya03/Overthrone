//! Windows Registry Hive Binary Parser
//!
//! Parses offline registry hive files (regf format) as saved by `reg save`.
//! Supports navigating keys, reading values, and extracting class names —
//! everything needed for SAM/SYSTEM/SECURITY hive credential extraction.
//!
//! Reference: <https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md>

use crate::error::{OverthroneError, Result};
use std::collections::HashMap;
use tracing::{debug, warn};

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

const REGF_MAGIC: &[u8; 4] = b"regf";
const HBIN_MAGIC: &[u8; 4] = b"hbin";
const NK_SIGNATURE: u16 = 0x6B6E; // "nk"
const VK_SIGNATURE: u16 = 0x6B76; // "vk"
const LF_SIGNATURE: u16 = 0x666C; // "lf"
const LH_SIGNATURE: u16 = 0x686C; // "lh"
const RI_SIGNATURE: u16 = 0x6972; // "ri"

/// Data is stored inline in the offset field when data_length high bit is set
const VALUE_COMP_NAME: u16 = 0x0001;
const DATA_IN_OFFSET: u32 = 0x80000000;

/// Registry value types
#[allow(dead_code)]
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;


// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

/// Parsed registry hive
pub struct RegistryHive {
    /// Raw hive data
    data: Vec<u8>,
    /// Offset to root key cell (relative to first hbin)
    root_cell_offset: u32,
    /// Start of hbin data (always 0x1000)
    hbin_start: usize,
}

/// A registry key node
#[derive(Debug, Clone)]
pub struct RegKey {
    /// Absolute offset within hive data
    pub offset: usize,
    /// Key name
    pub name: String,
    /// Number of subkeys
    pub subkey_count: u32,
    /// Offset to subkey list (relative)
    pub subkey_list_offset: i32,
    /// Number of values
    pub value_count: u32,
    /// Offset to value list (relative)
    pub value_list_offset: i32,
    /// Class name (used for boot key extraction)
    pub class_name: Option<String>,
    /// Class name offset
    pub class_name_offset: i32,
    /// Class name length
    pub class_name_length: u16,
}

/// A registry value
#[derive(Debug, Clone)]
pub struct RegValue {
    /// Value name (empty = "(Default)")
    pub name: String,
    /// Value type (REG_SZ, REG_BINARY, etc.)
    pub data_type: u32,
    /// Raw data bytes
    pub data: Vec<u8>,
}


// ═══════════════════════════════════════════════════════════
// Hive Parser
// ═══════════════════════════════════════════════════════════

impl RegistryHive {
    /// Parse a registry hive from raw bytes (as saved by `reg save`)
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        if data.len() < 0x1000 {
            return Err(OverthroneError::custom("Registry hive too small"));
        }

        // Validate regf header
        if &data[0..4] != REGF_MAGIC {
            return Err(OverthroneError::custom("Invalid registry hive: bad magic"));
        }

        // Root cell offset is at header offset 0x24
        let root_cell_offset = u32::from_le_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]);

        debug!(
            "Registry hive: {} bytes, root cell offset=0x{:x}",
            data.len(),
            root_cell_offset
        );

        Ok(Self {
            data,
            root_cell_offset,
            hbin_start: 0x1000,
        })
    }

    /// Get the root key
    pub fn root_key(&self) -> Result<RegKey> {
        let abs_offset = self.hbin_start + self.root_cell_offset as usize;
        self.parse_nk_cell(abs_offset)
    }

    /// Navigate to a subkey by path (e.g., "SAM\\Domains\\Account\\Users")
    pub fn open_key(&self, path: &str) -> Result<RegKey> {
        let mut current = self.root_key()?;

        for component in path.split('\\').filter(|s| !s.is_empty()) {
            current = self.find_subkey(&current, component)?;
        }

        Ok(current)
    }

    /// Find a subkey by name (case-insensitive)
    pub fn find_subkey(&self, parent: &RegKey, name: &str) -> Result<RegKey> {
        let subkeys = self.enum_subkeys(parent)?;
        for sk in &subkeys {
            if sk.name.eq_ignore_ascii_case(name) {
                return Ok(sk.clone());
            }
        }
        Err(OverthroneError::custom(format!(
            "Subkey '{}' not found under '{}'",
            name, parent.name
        )))
    }

    /// Enumerate all subkeys of a key
    pub fn enum_subkeys(&self, key: &RegKey) -> Result<Vec<RegKey>> {
        if key.subkey_count == 0 || key.subkey_list_offset == -1 {
            return Ok(Vec::new());
        }

        let list_offset = self.hbin_start + key.subkey_list_offset as usize;
        self.parse_subkey_list(list_offset)
    }

    /// Enumerate all values of a key
    pub fn enum_values(&self, key: &RegKey) -> Result<Vec<RegValue>> {
        if key.value_count == 0 || key.value_list_offset == -1 {
            return Ok(Vec::new());
        }

        let list_offset = self.hbin_start + key.value_list_offset as usize;
        let mut values = Vec::new();

        for i in 0..key.value_count as usize {
            let ptr_offset = list_offset + 4 + (i * 4); // skip cell size
            if ptr_offset + 4 > self.data.len() {
                break;
            }
            let vk_offset_rel = self.read_i32(ptr_offset);
            let vk_offset = self.hbin_start + vk_offset_rel as usize;
            if let Ok(val) = self.parse_vk_cell(vk_offset) {
                values.push(val);
            }
        }

        Ok(values)
    }

    /// Get a specific value by name
    pub fn get_value(&self, key: &RegKey, name: &str) -> Result<RegValue> {
        let values = self.enum_values(key)?;
        for v in &values {
            if v.name.eq_ignore_ascii_case(name) || (v.name.is_empty() && name == "(Default)") {
                return Ok(v.clone());
            }
        }
        Err(OverthroneError::custom(format!(
            "Value '{}' not found in '{}'",
            name, key.name
        )))
    }

    /// Get the class name of a key (critical for boot key extraction)
    pub fn get_class_name(&self, key: &RegKey) -> Option<String> {
        if key.class_name_offset == -1 || key.class_name_length == 0 {
            return None;
        }
        let offset = self.hbin_start + key.class_name_offset as usize + 4; // skip cell size
        let len = key.class_name_length as usize;
        if offset + len > self.data.len() {
            return None;
        }
        // Class names are UTF-16LE
        let bytes = &self.data[offset..offset + len];
        Some(utf16le_to_string(bytes))
    }

    // ───────────────────────────────────────────────────────
    // Internal cell parsers
    // ───────────────────────────────────────────────────────

    fn parse_nk_cell(&self, offset: usize) -> Result<RegKey> {
        // Cell layout: [size:i32][sig:u16][flags:u16][timestamp:u64]...
        if offset + 0x50 > self.data.len() {
            return Err(OverthroneError::custom("NK cell out of bounds"));
        }

        let sig = self.read_u16(offset + 4);
        if sig != NK_SIGNATURE {
            return Err(OverthroneError::custom(format!(
                "Expected NK signature at 0x{:x}, got 0x{:04x}",
                offset, sig
            )));
        }

        let flags = self.read_u16(offset + 6);
        let subkey_count = self.read_u32(offset + 0x18);
        let subkey_list_offset = self.read_i32(offset + 0x20);
        let value_count = self.read_u32(offset + 0x28);
        let value_list_offset = self.read_i32(offset + 0x2C);
        let class_name_offset = self.read_i32(offset + 0x34);
        let class_name_length = self.read_u16(offset + 0x4C);
        let name_length = self.read_u16(offset + 0x4E) as usize;

        // Key name starts at offset + 0x50
        let name_start = offset + 0x50;
        let name = if flags & VALUE_COMP_NAME != 0 {
            // ASCII (compressed) name
            String::from_utf8_lossy(&self.data[name_start..name_start + name_length]).to_string()
        } else {
            // UTF-16LE name
            utf16le_to_string(&self.data[name_start..name_start + name_length])
        };

        let mut key = RegKey {
            offset,
            name,
            subkey_count,
            subkey_list_offset,
            value_count,
            value_list_offset,
            class_name: None,
            class_name_offset,
            class_name_length,
        };

        // Eagerly resolve class name
        key.class_name = self.get_class_name(&key);

        Ok(key)
    }

    fn parse_vk_cell(&self, offset: usize) -> Result<RegValue> {
        if offset + 0x18 > self.data.len() {
            return Err(OverthroneError::custom("VK cell out of bounds"));
        }

        let sig = self.read_u16(offset + 4);
        if sig != VK_SIGNATURE {
            return Err(OverthroneError::custom("Bad VK signature"));
        }

        let name_length = self.read_u16(offset + 6) as usize;
        let data_length_raw = self.read_u32(offset + 8);
        let data_offset_raw = self.read_u32(offset + 0x0C);
        let data_type = self.read_u32(offset + 0x10);
        let flags = self.read_u16(offset + 0x14);

        // Value name
        let name = if name_length > 0 {
            let name_start = offset + 0x18;
            if flags & VALUE_COMP_NAME != 0 {
                String::from_utf8_lossy(&self.data[name_start..name_start + name_length])
                    .to_string()
            } else {
                utf16le_to_string(&self.data[name_start..name_start + name_length])
            }
        } else {
            String::new() // (Default) value
        };

        // Value data
        let data = if data_length_raw & DATA_IN_OFFSET != 0 {
            // Data stored inline in the offset field (small values ≤ 4 bytes)
            let real_len = (data_length_raw & 0x7FFFFFFF) as usize;
            let len = real_len.min(4);
            data_offset_raw.to_le_bytes()[..len].to_vec()
        } else if data_length_raw == 0 {
            Vec::new()
        } else {
            let real_len = data_length_raw as usize;
            let data_abs = self.hbin_start + data_offset_raw as usize + 4; // skip cell size
            if data_abs + real_len <= self.data.len() {
                self.data[data_abs..data_abs + real_len].to_vec()
            } else {
                warn!("VK data out of bounds: offset=0x{:x} len={}", data_abs, real_len);
                Vec::new()
            }
        };

        Ok(RegValue { name, data_type, data })
    }

    fn parse_subkey_list(&self, offset: usize) -> Result<Vec<RegKey>> {
        if offset + 8 > self.data.len() {
            return Ok(Vec::new());
        }

        let sig = self.read_u16(offset + 4);
        let count = self.read_u16(offset + 6) as usize;

        match sig {
            LF_SIGNATURE | LH_SIGNATURE => {
                // Each entry: [offset:i32][hash:u32]
                let mut keys = Vec::new();
                for i in 0..count {
                    let entry_offset = offset + 8 + (i * 8);
                    let nk_offset_rel = self.read_i32(entry_offset);
                    let nk_offset = self.hbin_start + nk_offset_rel as usize;
                    if let Ok(key) = self.parse_nk_cell(nk_offset) {
                        keys.push(key);
                    }
                }
                Ok(keys)
            }
            RI_SIGNATURE => {
                // Index root: each entry points to another subkey list
                let mut keys = Vec::new();
                for i in 0..count {
                    let entry_offset = offset + 8 + (i * 4);
                    let list_offset_rel = self.read_i32(entry_offset);
                    let list_offset = self.hbin_start + list_offset_rel as usize;
                    if let Ok(mut sub_keys) = self.parse_subkey_list(list_offset) {
                        keys.append(&mut sub_keys);
                    }
                }
                Ok(keys)
            }
            _ => {
                warn!("Unknown subkey list signature: 0x{:04x}", sig);
                Ok(Vec::new())
            }
        }
    }

    // ───────────────────────────────────────────────────────
    // Read helpers
    // ───────────────────────────────────────────────────────

    #[inline]
    fn read_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.data[offset], self.data[offset + 1]])
    }

    #[inline]
    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    #[inline]
    fn read_i32(&self, offset: usize) -> i32 {
        i32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }
}


// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

/// Decode UTF-16LE bytes to String
fn utf16le_to_string(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
        .trim_end_matches('\0')
        .to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf16le_to_string() {
        // "AB" in UTF-16LE
        let bytes = [0x41, 0x00, 0x42, 0x00];
        assert_eq!(utf16le_to_string(&bytes), "AB");
    }

    #[test]
    fn test_utf16le_with_null() {
        let bytes = [0x41, 0x00, 0x00, 0x00];
        assert_eq!(utf16le_to_string(&bytes), "A");
    }
}
