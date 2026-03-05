//! Windows Registry Hive Binary Parser + Remote WINREG RPC
//!
//! # Offline Hive Parser
//!
//! Parses offline registry hive files (regf format) as saved by `reg save`.
//! Supports navigating keys, reading values, and extracting class names —
//! everything needed for SAM/SYSTEM/SECURITY hive credential extraction.
//!
//! # Remote WINREG RPC
//!
//! Provides remote registry access via DCE/RPC over SMB named pipes.
//! Uses the `\pipe\winreg` endpoint for reading/writing registry values
//! on remote Windows systems.
//!
//! Reference: <https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md>
//! Reference: MS-RRP (Remote Registry Protocol)

use crate::error::{OverthroneError, Result};
use std::collections::HashMap;
use tracing::{debug, info, warn};

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


// ═══════════════════════════════════════════════════════════
// Remote WINREG RPC (MS-RRP)
// ═══════════════════════════════════════════════════════════

/// WINREG interface UUID
pub const WINREG_UUID: &str = "338cd001-2244-31f1-aaaa-900038001003";
pub const WINREG_VERSION: u16 = 1;

/// WINREG opnums
pub mod winreg_opnum {
    pub const OPEN_LOCAL_MACHINE: u16 = 0;
    pub const OPEN_CLASSES_ROOT: u16 = 1;
    pub const OPEN_CURRENT_USER: u16 = 2;
    pub const OPEN_PERFORMANCE_DATA: u16 = 3;
    pub const OPEN_USERS: u16 = 4;
    pub const OPEN_KEY: u16 = 5;
    pub const QUERY_VALUE: u16 = 6;
    pub const SET_VALUE: u16 = 7;
    pub const CREATE_KEY: u16 = 8;
    pub const ENUM_KEY: u16 = 9;
    pub const ENUM_VALUE: u16 = 10;
    pub const CLOSE_KEY: u16 = 14;
    pub const DELETE_KEY: u16 = 15;
    pub const DELETE_VALUE: u16 = 16;
    pub const GET_KEY_SECURITY: u16 = 19;
    pub const SET_KEY_SECURITY: u16 = 20;
}

/// Predefined registry hive handles (HKEY_*)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PredefinedHive {
    /// HKEY_CLASSES_ROOT
    ClassesRoot,
    /// HKEY_CURRENT_USER
    CurrentUser,
    /// HKEY_LOCAL_MACHINE
    LocalMachine,
    /// HKEY_USERS
    Users,
    /// HKEY_PERFORMANCE_DATA
    PerformanceData,
}

impl PredefinedHive {
    /// Get the WINREG opnum for opening this hive
    pub fn open_opnum(&self) -> u16 {
        match self {
            Self::ClassesRoot => winreg_opnum::OPEN_CLASSES_ROOT,
            Self::CurrentUser => winreg_opnum::OPEN_CURRENT_USER,
            Self::LocalMachine => winreg_opnum::OPEN_LOCAL_MACHINE,
            Self::Users => winreg_opnum::OPEN_USERS,
            Self::PerformanceData => winreg_opnum::OPEN_PERFORMANCE_DATA,
        }
    }
}

/// Remote registry session via WINREG RPC over SMB
pub struct RemoteRegistry {
    /// SMB tree connect to \\host\IPC$
    tree_id: u16,
    /// WINREG RPC handle (opened via Bind)
    bind_handle: Option<[u8; 20]>,
    /// Current open key handle
    key_handles: HashMap<u32, [u8; 20]>,
    /// Next key handle ID
    next_handle_id: u32,
}

/// Remote registry value
#[derive(Debug, Clone)]
pub struct RemoteRegValue {
    /// Value name
    pub name: String,
    /// Value type
    pub data_type: u32,
    /// Raw data
    pub data: Vec<u8>,
}

/// Remote registry key info
#[derive(Debug, Clone)]
pub struct RemoteRegKeyInfo {
    /// Key name
    pub name: String,
    /// Last write time (FILETIME)
    pub last_write_time: u64,
    /// Number of subkeys
    pub subkey_count: u32,
    /// Number of values
    pub value_count: u32,
}

impl RemoteRegistry {
    /// Create a new remote registry session
    pub fn new() -> Self {
        Self {
            tree_id: 0,
            bind_handle: None,
            key_handles: HashMap::new(),
            next_handle_id: 1,
        }
    }

    /// Build DCE/RPC Bind request for WINREG
    pub fn build_bind_request(&self, call_id: u32) -> Vec<u8> {
        // RPC version 5.0, packet type Bind (11), flags PFC_FIRST_FRAG | PFC_LAST_FRAG
        let mut pkt = vec![0x05, 0x00, 0x0B, 0x03];

        // Data representation (little-endian, ASCII, IEEE float)
        pkt.extend_from_slice(&0x00000010u32.to_le_bytes());

        // Fragment length (will update later)
        let frag_len_offset = pkt.len();
        pkt.extend_from_slice(&0u16.to_le_bytes());

        // Auth length
        pkt.extend_from_slice(&0u16.to_le_bytes());

        // Call ID
        pkt.extend_from_slice(&call_id.to_le_bytes());

        // Max xmit frag
        pkt.extend_from_slice(&0x0BDCu16.to_le_bytes());
        // Max recv frag
        pkt.extend_from_slice(&0x0BDCu16.to_le_bytes());

        // Assoc group
        pkt.extend_from_slice(&0u32.to_le_bytes());

        // Num ctx items
        pkt.push(0x01);
        // Padding
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Context item
        // Container ID
        pkt.extend_from_slice(&0u32.to_le_bytes());
        // Num trans items
        pkt.push(0x01);
        // Padding
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Interface UUID (WINREG)
        let uuid_bytes = parse_uuid(WINREG_UUID);
        pkt.extend_from_slice(&uuid_bytes);

        // Interface version
        pkt.extend_from_slice(&WINREG_VERSION.to_le_bytes());
        // Minor version
        pkt.extend_from_slice(&0u16.to_le_bytes());

        // Transfer syntax UUID (NDR)
        pkt.extend_from_slice(&parse_uuid("8a885d04-1ceb-11c9-9fe8-08002b104860"));
        // Transfer syntax version
        pkt.extend_from_slice(&2u32.to_le_bytes());

        // Update fragment length
        let frag_len = pkt.len() as u16;
        pkt[frag_len_offset..frag_len_offset + 2].copy_from_slice(&frag_len.to_le_bytes());

        pkt
    }

    /// Build OpenLocalMachine request
    pub fn build_open_hive_request(&self, hive: PredefinedHive, call_id: u32) -> Vec<u8> {
        self.build_open_hive_ex_request(hive, call_id, 0x00020019) // KEY_READ | KEY_WRITE
    }

    /// Build OpenHive request with custom access mask
    pub fn build_open_hive_ex_request(
        &self,
        _hive: PredefinedHive,
        call_id: u32,
        access_mask: u32,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // RPC header
        pkt.extend_from_slice(&build_rpc_header(0x00, call_id)); // Request

        // Opnum (varies by hive)
        let opnum = match _hive {
            PredefinedHive::LocalMachine => winreg_opnum::OPEN_LOCAL_MACHINE,
            PredefinedHive::ClassesRoot => winreg_opnum::OPEN_CLASSES_ROOT,
            PredefinedHive::CurrentUser => winreg_opnum::OPEN_CURRENT_USER,
            PredefinedHive::Users => winreg_opnum::OPEN_USERS,
            PredefinedHive::PerformanceData => winreg_opnum::OPEN_PERFORMANCE_DATA,
        };

        // Allocate hint
        pkt.extend_from_slice(&0u32.to_le_bytes());
        // Context handle (null for initial call)
        pkt.extend_from_slice(&[0u8; 20]);
        // Access mask
        pkt.extend_from_slice(&access_mask.to_le_bytes());
        // Opnum in header
        pkt.extend_from_slice(&opnum.to_le_bytes());

        pkt
    }

    /// Build OpenKey request
    pub fn build_open_key_request(
        &self,
        parent_handle: &[u8; 20],
        subkey_name: &str,
        call_id: u32,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // RPC header
        pkt.extend_from_slice(&build_rpc_header(0x00, call_id));

        // Parent key handle
        pkt.extend_from_slice(parent_handle);

        // Subkey name (RPC_UNICODE_STRING)
        let name_utf16: Vec<u8> = subkey_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        pkt.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&name_utf16);

        // Pad to 4-byte alignment
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }

        // Access mask (KEY_READ)
        pkt.extend_from_slice(&0x00020019u32.to_le_bytes());

        // Opnum
        pkt.extend_from_slice(&winreg_opnum::OPEN_KEY.to_le_bytes());

        pkt
    }

    /// Build QueryValue request
    pub fn build_query_value_request(
        &self,
        key_handle: &[u8; 20],
        value_name: &str,
        call_id: u32,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // RPC header
        pkt.extend_from_slice(&build_rpc_header(0x00, call_id));

        // Key handle
        pkt.extend_from_slice(key_handle);

        // Value name (RPC_UNICODE_STRING)
        let name_utf16: Vec<u8> = value_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        pkt.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&name_utf16);

        // Pad to 4-byte alignment
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }

        // Value type pointer (NULL - we want it returned)
        pkt.extend_from_slice(&0u32.to_le_bytes());

        // Data length pointer (NULL - we want it returned)
        pkt.extend_from_slice(&0u32.to_le_bytes());

        // Data pointer (NULL - we want it returned)
        pkt.extend_from_slice(&0u32.to_le_bytes());

        // Opnum
        pkt.extend_from_slice(&winreg_opnum::QUERY_VALUE.to_le_bytes());

        pkt
    }

    /// Build SetValue request
    pub fn build_set_value_request(
        &self,
        key_handle: &[u8; 20],
        value_name: &str,
        value_type: u32,
        data: &[u8],
        call_id: u32,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // RPC header
        pkt.extend_from_slice(&build_rpc_header(0x00, call_id));

        // Key handle
        pkt.extend_from_slice(key_handle);

        // Value name (RPC_UNICODE_STRING)
        let name_utf16: Vec<u8> = value_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        pkt.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        pkt.extend_from_slice(&name_utf16);

        // Pad to 4-byte alignment
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }

        // Value type
        pkt.extend_from_slice(&value_type.to_le_bytes());

        // Data length
        pkt.extend_from_slice(&(data.len() as u32).to_le_bytes());

        // Data
        pkt.extend_from_slice(data);

        // Pad to 4-byte alignment
        while pkt.len() % 4 != 0 {
            pkt.push(0);
        }

        // Opnum
        pkt.extend_from_slice(&winreg_opnum::SET_VALUE.to_le_bytes());

        pkt
    }

    /// Build CloseKey request
    pub fn build_close_key_request(&self, key_handle: &[u8; 20], call_id: u32) -> Vec<u8> {
        let mut pkt = Vec::new();

        // RPC header
        pkt.extend_from_slice(&build_rpc_header(0x00, call_id));

        // Key handle
        pkt.extend_from_slice(key_handle);

        // Opnum
        pkt.extend_from_slice(&winreg_opnum::CLOSE_KEY.to_le_bytes());

        pkt
    }

    /// Parse OpenHive response and extract the key handle
    pub fn parse_open_hive_response(&mut self, response: &[u8]) -> Result<[u8; 20]> {
        // Skip to the handle (after RPC header ~24 bytes + status)
        if response.len() < 48 {
            return Err(OverthroneError::custom("OpenHive response too short"));
        }

        let mut handle = [0u8; 20];
        handle.copy_from_slice(&response[24..44]);

        info!("RemoteRegistry: Opened hive, handle={:02x?}", &handle[..8]);
        Ok(handle)
    }

    /// Parse QueryValue response
    pub fn parse_query_value_response(&self, response: &[u8]) -> Result<RemoteRegValue> {
        if response.len() < 32 {
            return Err(OverthroneError::custom("QueryValue response too short"));
        }

        // Parse the response structure
        // [RPC header][type:u32][len:u32][data...]
        let offset = 24; // Skip RPC header
        let data_type = u32::from_le_bytes(response[offset..offset + 4].try_into().unwrap());
        let data_len = u32::from_le_bytes(response[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if offset + 8 + data_len > response.len() {
            return Err(OverthroneError::custom("QueryValue data truncated"));
        }

        let data = response[offset + 8..offset + 8 + data_len].to_vec();

        Ok(RemoteRegValue {
            name: String::new(), // Name was in request
            data_type,
            data,
        })
    }

    /// Store a key handle and return a local ID
    pub fn store_handle(&mut self, handle: [u8; 20]) -> u32 {
        let id = self.next_handle_id;
        self.next_handle_id += 1;
        self.key_handles.insert(id, handle);
        id
    }

    /// Get a key handle by ID
    pub fn get_handle(&self, id: u32) -> Option<&[u8; 20]> {
        self.key_handles.get(&id)
    }

    /// Remove a key handle
    pub fn remove_handle(&mut self, id: u32) -> Option<[u8; 20]> {
        self.key_handles.remove(&id)
    }
}

impl Default for RemoteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════
// WINREG RPC Helpers
// ═══════════════════════════════════════════════════════════

/// Parse a UUID string to bytes
fn parse_uuid(uuid_str: &str) -> [u8; 16] {
    let clean = uuid_str.replace('-', "");
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        if let Ok(b) = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16) {
            bytes[i] = b;
        }
    }
    bytes
}

/// Build a minimal DCE/RPC request header
fn build_rpc_header(_packet_type: u8, call_id: u32) -> Vec<u8> {
    // RPC version 5.0, packet type Request (0), flags PFC_FIRST_FRAG | PFC_LAST_FRAG
    let mut hdr = vec![0x05, 0x00, 0x00, 0x03];

    // Data representation (little-endian)
    hdr.extend_from_slice(&0x00000010u32.to_le_bytes());

    // Fragment length (placeholder)
    hdr.extend_from_slice(&0u16.to_le_bytes());

    // Auth length
    hdr.extend_from_slice(&0u16.to_le_bytes());

    // Call ID
    hdr.extend_from_slice(&call_id.to_le_bytes());

    // Alloc hint
    hdr.extend_from_slice(&0u32.to_le_bytes());

    // Context ID
    hdr.extend_from_slice(&0u16.to_le_bytes());

    // Opnum (placeholder)
    hdr.extend_from_slice(&0u16.to_le_bytes());

    hdr
}

// ═══════════════════════════════════════════════════════════
// High-Level Remote Registry Operations
// ═══════════════════════════════════════════════════════════

/// Read a remote registry value via WINREG DCE/RPC over SMB named pipe.
///
/// Orchestrates the full WINREG RPC conversation: Bind → OpenHive → OpenKey
/// (for each path segment) → QueryValue → CloseKey (all handles).
///
/// # Arguments
/// * `smb_session` - Active SMB session with IPC$ access
/// * `hive` - Predefined hive (HKLM, HKCU, etc.)
/// * `path` - Registry path (e.g., "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
/// * `value_name` - Value to read (empty string for default value)
pub async fn read_remote_registry_value(
    smb_session: &mut crate::proto::smb::SmbSession,
    hive: PredefinedHive,
    path: &str,
    value_name: &str,
) -> Result<RemoteRegValue> {
    let mut reg = RemoteRegistry::new();
    let pipe = "winreg";
    let mut call_id = 1u32;

    // 1. DCE/RPC Bind to WINREG interface
    let bind_req = reg.build_bind_request(call_id);
    call_id += 1;
    let bind_resp = smb_session.pipe_transact(pipe, &bind_req).await
        .map_err(|e| OverthroneError::custom(format!("WINREG bind transport failed: {e}")))?;
    if bind_resp.len() < 4 || bind_resp[2] != 12 {
        return Err(OverthroneError::custom("WINREG RPC bind rejected by server"));
    }
    info!("RemoteRegistry: RPC bind to WINREG accepted");

    // 2. Open the predefined hive
    let open_hive_req = reg.build_open_hive_request(hive, call_id);
    call_id += 1;
    let open_hive_resp = smb_session.pipe_transact(pipe, &open_hive_req).await
        .map_err(|e| OverthroneError::custom(format!("OpenHive failed: {e}")))?;
    let hive_handle = reg.parse_open_hive_response(&open_hive_resp)?;

    // Track all opened handles for cleanup (in order opened)
    let mut opened_handles: Vec<[u8; 20]> = vec![hive_handle];
    let mut current_handle = hive_handle;

    // 3. Walk the registry path, opening each subkey
    let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
    for part in &parts {
        let open_key_req = reg.build_open_key_request(&current_handle, part, call_id);
        call_id += 1;
        let open_key_resp = match smb_session.pipe_transact(pipe, &open_key_req).await {
            Ok(resp) => resp,
            Err(e) => {
                // Clean up all opened handles before returning
                for h in opened_handles.iter().rev() {
                    let close_req = reg.build_close_key_request(h, call_id);
                    call_id += 1;
                    let _ = smb_session.pipe_transact(pipe, &close_req).await;
                }
                return Err(OverthroneError::custom(format!(
                    "Failed to open registry key '{}': {}", part, e
                )));
            }
        };

        if open_key_resp.len() < 48 {
            for h in opened_handles.iter().rev() {
                let close_req = reg.build_close_key_request(h, call_id);
                call_id += 1;
                let _ = smb_session.pipe_transact(pipe, &close_req).await;
            }
            return Err(OverthroneError::custom(format!(
                "OpenKey response too short for '{}'", part
            )));
        }

        let mut key_handle = [0u8; 20];
        key_handle.copy_from_slice(&open_key_resp[24..44]);
        opened_handles.push(key_handle);
        current_handle = key_handle;
    }

    // 4. Query the value
    let query_req = reg.build_query_value_request(&current_handle, value_name, call_id);
    call_id += 1;
    let query_resp = smb_session.pipe_transact(pipe, &query_req).await;

    // 5. Close all handles in reverse order (best-effort)
    for h in opened_handles.iter().rev() {
        let close_req = reg.build_close_key_request(h, call_id);
        call_id += 1;
        let _ = smb_session.pipe_transact(pipe, &close_req).await;
    }

    // 6. Parse and return the result (after cleanup)
    let query_resp = query_resp
        .map_err(|e| OverthroneError::custom(format!("QueryValue failed: {e}")))?;
    let mut value = reg.parse_query_value_response(&query_resp)?;
    value.name = value_name.to_string();

    info!("RemoteRegistry: Read value '{}' (type={}, {} bytes)",
        value_name, value.data_type, value.data.len());
    Ok(value)
}

/// Common remote registry paths for security assessments
pub mod registry_paths {
    /// Windows Defender exclusion paths
    pub const DEFENDER_EXCLUSIONS: &str = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
    /// LSA configuration
    pub const LSA_CONFIG: &str = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
    /// Cached domain logons
    pub const CACHED_LOGONS: &str = "SECURITY\\Cache";
    /// SAM account keys
    pub const SAM_ACCOUNTS: &str = "SAM\\Domains\\Account\\Users";
    /// Boot key (for decrypting SAM/SECURITY)
    pub const BOOT_KEY_PATH: &str = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
    /// Run keys (persistence)
    pub const RUN_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    /// Service configuration
    pub const SERVICES_PATH: &str = "SYSTEM\\CurrentControlSet\\Services";
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

    #[test]
    fn test_parse_uuid() {
        let uuid = parse_uuid(WINREG_UUID);
        assert_eq!(uuid.len(), 16);
        assert_eq!(uuid[0], 0x33);
        assert_eq!(uuid[1], 0x8c);
    }

    #[test]
    fn test_build_bind_request() {
        let reg = RemoteRegistry::new();
        let bind = reg.build_bind_request(1);
        assert!(bind.len() > 50);
        assert_eq!(bind[0], 0x05); // Version
        assert_eq!(bind[2], 0x0B); // Bind packet type
    }

    #[test]
    fn test_predefined_hive_opnum() {
        assert_eq!(PredefinedHive::LocalMachine.open_opnum(), 0);
        assert_eq!(PredefinedHive::ClassesRoot.open_opnum(), 1);
        assert_eq!(PredefinedHive::Users.open_opnum(), 4);
    }

    #[test]
    fn test_remote_registry_handle_storage() {
        let mut reg = RemoteRegistry::new();
        let handle = [0xAA; 20];
        let id = reg.store_handle(handle);
        assert_eq!(id, 1);

        let retrieved = reg.get_handle(id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap()[0], 0xAA);

        let removed = reg.remove_handle(id);
        assert!(removed.is_some());
        assert!(reg.get_handle(id).is_none());
    }
}
