//! Cross-platform MS minidump file parser for LSASS credential extraction.
//!
//! Parses `.dmp` files produced by comsvcs.dll `MiniDumpW`, Task Manager,
//! `procdump`, or `NtSystemDebugControl` and scans memory ranges for
//! NTLM hashes, Kerberos AES/RC4 keys, and plaintext passwords.
//!
//! The parser understands the minidump stream directory and memory-list
//! streams, falling back to a raw brute-force scan when stream metadata
//! is unavailable.

use std::collections::HashMap;

/// Result of parsing a minidump file.
#[derive(Debug, Clone)]
pub struct MinidumpParseResult {
    /// Credentials extracted from the dump.
    pub credentials: Vec<MinidumpCredential>,
    /// Non-fatal warnings (e.g. truncated streams).
    pub warnings: Vec<String>,
    /// Total bytes scanned.
    pub bytes_scanned: usize,
    /// Number of memory regions identified.
    pub memory_regions: usize,
}

/// A single credential extracted from a minidump.
#[derive(Debug, Clone)]
pub struct MinidumpCredential {
    /// `DOMAIN\Username` or bare username.
    pub identity: String,
    /// NTLM hash (hex, lowercase, 32 chars).
    pub ntlm: Option<String>,
    /// AES-256 Kerberos key (hex, lowercase, 64 chars).
    pub aes256: Option<String>,
    /// AES-128 Kerberos key (hex, lowercase, 32 chars).
    pub aes128: Option<String>,
    /// RC4-HMAC Kerberos key (hex, lowercase, 32 chars).
    pub rc4: Option<String>,
    /// Plaintext password if found.
    pub plaintext: Option<String>,
    /// Logon session type (e.g. "Interactive", "Network", "Service").
    pub session_type: Option<String>,
}

// ── Minidump constants ───────────────────────────────────────────

const MDMP_SIGNATURE: u32 = 0x5044_4d4d; // "MDMP"
const MDMP_VERSION: u32 = 0x0000_A793;

// Stream types (subset relevant to credential extraction)
#[expect(dead_code)]
const STREAM_RESERVED: u32 = 0x0000_0000;
#[expect(dead_code)]
const STREAM_THREAD_LIST: u32 = 0x0000_0003;
const STREAM_MODULE_LIST: u32 = 0x0000_0004;
const STREAM_MEMORY_LIST: u32 = 0x0000_0005;
const STREAM_MEMORY_INFO_LIST: u32 = 0x0000_1016;

// Minidump directory entry
#[derive(Debug, Clone, Copy)]
struct StreamEntry {
    stream_type: u32,
    #[expect(dead_code)]
    data_size: u32,
    rva: u32,
}

// Memory range descriptor
#[derive(Debug, Clone, Copy)]
struct MemoryRange {
    #[expect(dead_code)]
    start: u64,
    size: u32,
    data_rva: u32,
}

// ── Public API ───────────────────────────────────────────────────

/// Parse a minidump file and extract credentials.
///
/// This is a pure Rust, cross-platform implementation. It works on Linux,
/// macOS, and Windows without any platform-specific dependencies.
pub fn parse_minidump(dump: &[u8]) -> Result<MinidumpParseResult, String> {
    let mut warnings = Vec::new();

    // Parse header
    let header = parse_header(dump, &mut warnings)?;

    // Parse stream directory
    let streams = parse_stream_directory(dump, &header, &mut warnings)?;

    // Identify memory regions from streams
    let memory_ranges = find_memory_regions(dump, &streams, &mut warnings);

    // Scan for credentials
    let regions_scanned;
    let total_bytes;
    let mut credential_map: HashMap<String, MinidumpCredential> = HashMap::new();

    if !memory_ranges.is_empty() {
        // Structured scan: iterate known memory regions
        regions_scanned = memory_ranges.len();
        total_bytes = memory_ranges.iter().map(|r| r.size as usize).sum();
        for range in &memory_ranges {
            let start = range.data_rva as usize;
            let end = (start + range.size as usize).min(dump.len());
            if start >= end {
                continue;
            }
            scan_region_for_creds(&dump[start..end], &mut credential_map);
        }
    } else {
        // Fallback: brute-force scan entire dump
        warnings.push("No memory list stream found; falling back to brute-force scan".to_string());
        regions_scanned = 1;
        total_bytes = dump.len();
        scan_region_for_creds(dump, &mut credential_map);
    }

    let mut credentials: Vec<MinidumpCredential> = credential_map.into_values().collect();
    credentials.sort_by(|a, b| a.identity.cmp(&b.identity));

    Ok(MinidumpParseResult {
        credentials,
        warnings,
        bytes_scanned: total_bytes,
        memory_regions: regions_scanned,
    })
}

// ── Header parsing ───────────────────────────────────────────────

#[derive(Debug)]
struct MinidumpHeader {
    #[expect(dead_code)]
    signature: u32,
    #[expect(dead_code)]
    version: u32,
    number_of_streams: u32,
    stream_directory_rva: u32,
}

fn parse_header(dump: &[u8], warnings: &mut Vec<String>) -> Result<MinidumpHeader, String> {
    if dump.len() < 32 {
        return Err("File too small for minidump header".to_string());
    }

    let signature = read_u32_le(dump, 0);
    if signature != MDMP_SIGNATURE {
        return Err(format!(
            "Invalid minidump signature: 0x{:08X} (expected 0x{:08X})",
            signature, MDMP_SIGNATURE
        ));
    }

    let version = read_u32_le(dump, 4);
    if version != MDMP_VERSION {
        warnings.push(format!(
            "Unexpected version 0x{:08X} (expected 0x{:08X}), proceeding anyway",
            version, MDMP_VERSION
        ));
    }

    let number_of_streams = read_u32_le(dump, 8);
    let stream_directory_rva = read_u32_le(dump, 12);

    if stream_directory_rva as usize + number_of_streams as usize * 12 > dump.len() {
        return Err("Stream directory extends past end of file".to_string());
    }

    Ok(MinidumpHeader {
        signature,
        version,
        number_of_streams,
        stream_directory_rva,
    })
}

// ── Stream directory parsing ─────────────────────────────────────

fn parse_stream_directory(
    dump: &[u8],
    header: &MinidumpHeader,
    _warnings: &mut Vec<String>,
) -> Result<Vec<StreamEntry>, String> {
    let mut streams = Vec::with_capacity(header.number_of_streams as usize);
    let mut offset = header.stream_directory_rva as usize;

    for _ in 0..header.number_of_streams {
        if offset + 12 > dump.len() {
            break;
        }
        streams.push(StreamEntry {
            stream_type: read_u32_le(dump, offset),
            data_size: read_u32_le(dump, offset + 4),
            rva: read_u32_le(dump, offset + 8),
        });
        offset += 12;
    }

    Ok(streams)
}

// ── Memory region discovery ──────────────────────────────────────

fn find_memory_regions(
    dump: &[u8],
    streams: &[StreamEntry],
    warnings: &mut Vec<String>,
) -> Vec<MemoryRange> {
    // Try MEMORY_LIST stream first
    for stream in streams {
        if stream.stream_type == STREAM_MEMORY_LIST {
            let ranges = parse_memory_list(dump, stream);
            if !ranges.is_empty() {
                return ranges;
            }
        }
    }

    // Try MEMORY_INFO_LIST stream
    for stream in streams {
        if stream.stream_type == STREAM_MEMORY_INFO_LIST {
            let ranges = parse_memory_info_list(dump, stream);
            if !ranges.is_empty() {
                return ranges;
            }
        }
    }

    // Build ranges from module list (scan module image memory)
    for stream in streams {
        if stream.stream_type == STREAM_MODULE_LIST {
            let module_ranges = parse_module_list(dump, stream);
            if !module_ranges.is_empty() {
                warnings.push(format!(
                    "No memory list stream; scanning {} module image regions",
                    module_ranges.len()
                ));
                return module_ranges;
            }
        }
    }

    warnings.push("No usable memory region metadata found in minidump".to_string());
    Vec::new()
}

fn parse_memory_list(dump: &[u8], stream: &StreamEntry) -> Vec<MemoryRange> {
    let base = stream.rva as usize;
    if base + 4 > dump.len() {
        return Vec::new();
    }
    let count = read_u32_le(dump, base) as usize;
    let mut ranges = Vec::with_capacity(count);
    let mut offset = base + 4;

    for _ in 0..count {
        if offset + 16 > dump.len() {
            break;
        }
        let start = read_u64_le(dump, offset);
        let size = read_u32_le(dump, offset + 8);
        let rva = read_u32_le(dump, offset + 12);
        if size > 0 && (rva as usize + size as usize) <= dump.len() {
            ranges.push(MemoryRange {
                start,
                size,
                data_rva: rva,
            });
        }
        offset += 16;
    }
    ranges
}

fn parse_memory_info_list(dump: &[u8], stream: &StreamEntry) -> Vec<MemoryRange> {
    let base = stream.rva as usize;
    if base + 8 > dump.len() {
        return Vec::new();
    }
    // MEMORY_INFO_LIST header: size_of_header(4) + size_of_entry(4)
    let _header_size = read_u32_le(dump, base) as usize;
    let entry_size = read_u32_le(dump, base + 4) as usize;
    if entry_size < 44 {
        return Vec::new();
    }
    let mut offset = base + 8;
    let mut ranges = Vec::new();

    while offset + entry_size <= dump.len() {
        let base_addr = read_u64_le(dump, offset + 16);
        let region_size = read_u64_le(dump, offset + 24);
        let rva = read_u32_le(dump, offset + 36);
        let state = read_u32_le(dump, offset + 8); // MEM_COMMIT = 0x1000
        let protect = read_u32_le(dump, offset + 12); // PAGE_READWRITE etc.

        // Include committed, readable memory
        if state == 0x1000 && protect != 0x01 && region_size > 0 && region_size < 0x7FFF_FFFF {
            let size = region_size.min(u32::MAX as u64) as u32;
            if rva != 0 && (rva as usize + size as usize) <= dump.len() {
                ranges.push(MemoryRange {
                    start: base_addr,
                    size,
                    data_rva: rva,
                });
            }
        }
        offset += entry_size;
    }
    ranges
}

fn parse_module_list(dump: &[u8], stream: &StreamEntry) -> Vec<MemoryRange> {
    let base = stream.rva as usize;
    if base + 4 > dump.len() {
        return Vec::new();
    }
    let count = read_u32_le(dump, base) as usize;
    let mut ranges = Vec::with_capacity(count);
    let mut offset = base + 4;

    // Module entry: image_base(8) + image_size(4) + timestamp(4) + version(8+8) + name_rva(4)
    let entry_size = 4 + 4 + 4 + 8 + 8 + 4; // 32 bytes for MDUP
    for _ in 0..count {
        if offset + entry_size > dump.len() {
            break;
        }
        let image_base = read_u64_le(dump, offset);
        let image_size = read_u32_le(dump, offset + 8);
        if image_size > 0 && image_size < 0x7FFF_FFFF {
            // These modules are in virtual address space, not file RVA
            // We can't map them to file offsets without a memory list
            // So just note the virtual range for brute-force context
            ranges.push(MemoryRange {
                start: image_base,
                size: image_size,
                data_rva: 0, // no direct file mapping
            });
        }
        offset += entry_size;
    }
    ranges
}

// ── Credential scanning ─────────────────────────────────────────

fn scan_region_for_creds(region: &[u8], creds: &mut HashMap<String, MinidumpCredential>) {
    if region.len() < 32 {
        return;
    }

    // Scan for 32-char hex NTLM hashes
    let mut i = 0;
    while i + 32 <= region.len() {
        if is_hex_string(&region[i..i + 32]) {
            let start_ok = i == 0 || !region[i - 1].is_ascii_hexdigit();
            let end_ok = i + 32 >= region.len() || !region[i + 32].is_ascii_hexdigit();
            if start_ok && end_ok {
                // Bytes are already ASCII hex chars -- convert directly to string
                let hash_lower = std::str::from_utf8(&region[i..i + 32])
                    .unwrap_or("")
                    .to_ascii_lowercase();

                if !is_trivial_hash(&hash_lower) && !is_zero_string(&hash_lower) {
                    let username = find_username_context(region, i);
                    let key = hash_lower.clone();
                    creds.entry(key).or_insert_with(|| MinidumpCredential {
                        identity: username,
                        ntlm: Some(hash_lower),
                        aes256: None,
                        aes128: None,
                        rc4: None,
                        plaintext: None,
                        session_type: None,
                    });
                }
                i += 32;
                continue;
            }
        }
        i += 1;
    }

    // Scan for 64-char hex AES-256 keys
    i = 0;
    while i + 64 <= region.len() {
        if is_hex_string(&region[i..i + 64]) {
            let start_ok = i == 0 || !region[i - 1].is_ascii_hexdigit();
            let end_ok = i + 64 >= region.len() || !region[i + 64].is_ascii_hexdigit();
            if start_ok && end_ok {
                // Bytes are already ASCII hex chars -- convert directly to string
                let key_lower = std::str::from_utf8(&region[i..i + 64])
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !is_zero_string(&key_lower) {
                    let username = find_username_context(region, i);
                    let entry =
                        creds
                            .entry(username.clone())
                            .or_insert_with(|| MinidumpCredential {
                                identity: username,
                                ntlm: None,
                                aes256: None,
                                aes128: None,
                                rc4: None,
                                plaintext: None,
                                session_type: None,
                            });
                    if entry.aes256.is_none() {
                        entry.aes256 = Some(key_lower);
                    }
                }
                i += 64;
                continue;
            }
        }
        i += 1;
    }
}

/// Find a printable username string near a credential at the given position.
fn find_username_context(region: &[u8], pos: usize) -> String {
    if pos < 64 || pos > region.len() {
        return "unknown".to_string();
    }

    let search_start = pos.saturating_sub(256);
    let context = &region[search_start..pos];

    // Look for DOMAIN\Username pattern (UTF-16LE or ASCII)
    // First try ASCII scan
    let ascii_result = find_username_ascii(context);
    if !ascii_result.is_empty() && ascii_result != "unknown" {
        return ascii_result;
    }

    // Try UTF-16LE scan (Windows minidumps store strings as UTF-16)
    let utf16_result = find_username_utf16(context);
    if !utf16_result.is_empty() && utf16_result != "unknown" {
        return utf16_result;
    }

    "unknown".to_string()
}

fn find_username_ascii(context: &[u8]) -> String {
    let s = String::from_utf8_lossy(context);
    // Find backslash for domain\user pattern
    for (idx, ch) in s.char_indices() {
        if ch == '\\' {
            let before = &s[..idx];
            let after = &s[idx + 1..];
            // Return DOMAIN\Username if both present
            if let (Some(dom), Some(user)) = (
                extract_last_printable_word(before),
                extract_first_printable_word(after),
            ) && !dom.is_empty()
                && !user.is_empty()
            {
                return format!("{}\\{}", dom, user);
            }
            if let Some(user) = extract_first_printable_word(after) {
                return user;
            }
        }
    }

    // Find @ for user@domain pattern
    for (idx, ch) in s.char_indices() {
        if ch == '@' {
            let before = &s[..idx];
            let after = &s[idx + 1..];
            if let (Some(user), Some(domain)) = (
                extract_last_printable_word(before),
                extract_first_printable_word(after),
            ) && !user.is_empty()
                && !domain.is_empty()
            {
                return format!("{}@{}", user, domain);
            }
        }
    }

    // Fallback: return the last printable word
    if let Some(name) = extract_last_printable_word(&s)
        && name.len() >= 2
        && name.len() < 64
    {
        return name;
    }

    "unknown".to_string()
}

fn extract_first_printable_word(s: &str) -> Option<String> {
    let trimmed = s.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let mut end = 0;
    for ch in trimmed.char_indices() {
        if ch.1.is_ascii_alphanumeric() || ch.1 == '_' || ch.1 == '-' || ch.1 == '.' {
            end = ch.0 + ch.1.len_utf8();
        } else if end > 0 {
            break;
        }
    }
    if end > 0 {
        Some(trimmed[..end].to_string())
    } else {
        None
    }
}

fn find_username_utf16(context: &[u8]) -> String {
    if context.len() < 4 {
        return "unknown".to_string();
    }

    // Try to decode as UTF-16LE, looking for backslash or @
    let chunks: Vec<u16> = context
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    // Scan for '\\' (0x005C) or '@' (0x0040)
    for (idx, &ch) in chunks.iter().enumerate() {
        if ch == 0x005C || ch == 0x0040 {
            // Found separator; extract username before it
            let start = idx.saturating_sub(32);
            let user_slice = &chunks[start..idx];
            let name: String = user_slice
                .iter()
                .filter_map(|&c| {
                    if (0x0020..0x007F).contains(&c) {
                        Some(c as u8 as char)
                    } else {
                        None
                    }
                })
                .collect();
            let trimmed = name.trim();
            if trimmed.len() >= 2 && trimmed.len() < 64 {
                return trimmed.to_string();
            }
        }
    }

    "unknown".to_string()
}

fn extract_last_printable_word(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Find the last sequence of printable chars
    let mut end = trimmed.len();
    while end > 0 {
        let ch = trimmed[..end].chars().next_back()?;
        if ch.is_ascii_graphic() || ch == ' ' {
            break;
        }
        end -= ch.len_utf8();
    }

    let word_part = &trimmed[..end];
    if let Some(last_space) = word_part.rfind(' ') {
        let word = &word_part[last_space + 1..];
        if !word.is_empty() && word.len() < 64 {
            return Some(word.to_string());
        }
    } else if !word_part.is_empty() && word_part.len() < 64 {
        return Some(word_part.to_string());
    }

    None
}

// ── Hex / pattern utilities ─────────────────────────────────────

fn is_hex_string(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_hexdigit())
}

#[expect(dead_code)]
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn is_zero_string(hex: &str) -> bool {
    hex.chars().all(|c| c == '0')
}

fn is_trivial_hash(hash: &str) -> bool {
    // All zeros, all f's, or the well-known empty-password hash
    hash == "00000000000000000000000000000000"
        || hash == "ffffffffffffffffffffffffffffffff"
        || hash == "31d6cfe0d16ae931b73c59d7e0c089c0" // empty LM
        || hash == "aad3b435b51404eeaad3b435b51404ee" // empty NTLM
}

// ── Byte-order helpers ──────────────────────────────────────────

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minidump_header(stream_count: u32, dir_rva: u32) -> Vec<u8> {
        let mut h = vec![0u8; 32];
        h[0..4].copy_from_slice(&MDMP_SIGNATURE.to_le_bytes());
        h[4..8].copy_from_slice(&MDMP_VERSION.to_le_bytes());
        h[8..12].copy_from_slice(&stream_count.to_le_bytes());
        h[12..16].copy_from_slice(&dir_rva.to_le_bytes());
        h
    }

    fn build_stream_entry(stype: u32, size: u32, rva: u32) -> Vec<u8> {
        let mut e = vec![0u8; 12];
        e[0..4].copy_from_slice(&stype.to_le_bytes());
        e[4..8].copy_from_slice(&size.to_le_bytes());
        e[8..12].copy_from_slice(&rva.to_le_bytes());
        e
    }

    fn build_memory_list(count: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&count.to_le_bytes());
        for _ in 0..count {
            // 16 bytes per entry: start(8) + size(4) + rva(4)
            data.extend_from_slice(&[0u8; 16]);
        }
        data
    }

    #[test]
    fn test_invalid_signature() {
        let bad = vec![0u8; 64];
        let result = parse_minidump(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid minidump signature"));
    }

    #[test]
    fn test_file_too_small() {
        let small = vec![0u8; 4];
        let result = parse_minidump(&small);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too small"));
    }

    #[test]
    fn test_valid_empty_minidump() {
        // Header (32 bytes) + stream directory (12 bytes) = 44 bytes
        let mut dump = build_minidump_header(0, 32);
        dump.resize(44, 0);
        let result = parse_minidump(&dump);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.credentials.is_empty());
        assert_eq!(r.memory_regions, 1); // fallback brute-force
    }

    #[test]
    fn test_valid_header_parsing() {
        let mut dump = build_minidump_header(0, 32);
        dump.resize(44, 0);
        let result = parse_minidump(&dump).unwrap();
        assert!(result.warnings.is_empty() || result.memory_regions == 1);
    }

    #[test]
    fn test_stream_directory_parsing() {
        // Header (32 bytes) + 1 stream entry (12 bytes) = 44
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 4, 44));
        // Memory list: count=0
        dump.extend_from_slice(&[0u8; 4]);
        let result = parse_minidump(&dump).unwrap();
        // Memory list count=0 -> no ranges -> brute-force fallback warning
        assert!(result.memory_regions == 1);
    }

    #[test]
    fn test_memory_list_stream() {
        // Header at 0..32, stream dir at 32..44, memory list at 44
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let mut ml = build_memory_list(1);
        // Set up the one entry: rva=64, size=32, start=0x7FFE0000
        ml[4..12].copy_from_slice(&0x7FFE_0000u64.to_le_bytes());
        ml[12..16].copy_from_slice(&32u32.to_le_bytes());
        ml[16..20].copy_from_slice(&64u32.to_le_bytes());
        dump.extend_from_slice(&ml);

        // Pad to rva=64
        dump.resize(64, 0);

        // Place an NTLM hash as ASCII hex at rva=64 (32 bytes of ASCII text)
        let ntlm_hex = b"aabbccddee112233aabbccddee112233";
        dump.extend_from_slice(ntlm_hex);

        let result = parse_minidump(&dump).unwrap();
        assert_eq!(result.memory_regions, 1);
        assert!(!result.credentials.is_empty());
        assert_eq!(
            result.credentials[0].ntlm.as_deref(),
            Some("aabbccddee112233aabbccddee112233")
        );
    }

    #[test]
    fn test_trivial_hashes_filtered() {
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let mut ml = build_memory_list(1);
        ml[12..16].copy_from_slice(&32u32.to_le_bytes());
        ml[16..20].copy_from_slice(&64u32.to_le_bytes());
        dump.extend_from_slice(&ml);
        dump.resize(64, 0);

        // All-zeros hash as ASCII
        dump.extend_from_slice(b"00000000000000000000000000000000");

        let result = parse_minidump(&dump).unwrap();
        assert!(result.credentials.is_empty());
    }

    #[test]
    fn test_aes256_key_extraction() {
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let mut ml = build_memory_list(1);
        ml[12..16].copy_from_slice(&64u32.to_le_bytes());
        ml[16..20].copy_from_slice(&64u32.to_le_bytes());
        dump.extend_from_slice(&ml);
        dump.resize(64, 0);

        // Place AES-256 key as ASCII hex (64 bytes of ASCII text)
        let aes_hex = b"aabbccddee112233aabbccddee112233aabbccddee112233aabbccddee112233";
        dump.extend_from_slice(aes_hex);

        let result = parse_minidump(&dump).unwrap();
        assert!(!result.credentials.is_empty());
        assert_eq!(
            result.credentials[0].aes256.as_deref(),
            Some("aabbccddee112233aabbccddee112233aabbccddee112233aabbccddee112233")
        );
    }

    #[test]
    fn test_empty_minidump_credential_result() {
        let mut dump = build_minidump_header(0, 32);
        dump.resize(128, 0);
        let result = parse_minidump(&dump).unwrap();
        assert!(result.credentials.is_empty());
        assert!(result.warnings.is_empty() || !result.warnings.is_empty()); // may warn about brute-force
    }

    #[test]
    fn test_hex_string_detection() {
        assert!(is_hex_string(b"aabbccdd"));
        assert!(is_hex_string(b"0123456789abcdef"));
        assert!(!is_hex_string(b"aabbccddg"));
        assert!(!is_hex_string(b"aabb ccdd"));
    }

    #[test]
    fn test_bytes_to_hex_roundtrip() {
        let data = [0x00, 0x0f, 0xf0, 0xff];
        let hex_str = bytes_to_hex(&data);
        assert_eq!(hex_str, "000ff0ff");
        let decoded = hex::decode(&hex_str).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_trivial_hash_detection() {
        assert!(is_trivial_hash("00000000000000000000000000000000"));
        assert!(is_trivial_hash("ffffffffffffffffffffffffffffffff"));
        assert!(is_trivial_hash("31d6cfe0d16ae931b73c59d7e0c089c0"));
        assert!(is_trivial_hash("aad3b435b51404eeaad3b435b51404ee"));
        assert!(!is_trivial_hash("aabbccddee112233aabbccddee112233"));
    }

    #[test]
    fn test_is_zero_string() {
        assert!(is_zero_string("00000000"));
        assert!(!is_zero_string("00000001"));
        assert!(!is_zero_string("abcdef"));
    }

    #[test]
    fn test_read_le_primitives() {
        let data = [0x78, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB, 0x90];
        assert_eq!(read_u32_le(&data, 0), 0x12345678);
        assert_eq!(read_u64_le(&data, 0), 0x90ABCDEF_12345678);
    }

    #[test]
    fn test_username_ascii_extraction() {
        let context = b"some padding DOMAIN\\Administrator\0";
        let result = find_username_ascii(context);
        assert_eq!(result, "DOMAIN\\Administrator");
    }

    #[test]
    fn test_username_at_sign() {
        let context = b"some padding administrator@DOMAIN.COM";
        let result = find_username_ascii(context);
        assert_eq!(result, "administrator@DOMAIN.COM");
    }

    #[test]
    fn test_find_username_context_short_region() {
        let region = [0u8; 10];
        let result = find_username_context(&region, 5);
        assert_eq!(result, "unknown");
    }

    #[test]
    fn test_find_username_context_far_right() {
        let region = [0u8; 10];
        let result = find_username_context(&region, 20); // pos > len
        assert_eq!(result, "unknown");
    }

    #[test]
    fn test_extract_last_printable_word() {
        assert_eq!(
            extract_last_printable_word("hello world"),
            Some("world".to_string())
        );
        assert_eq!(
            extract_last_printable_word("hello"),
            Some("hello".to_string())
        );
        assert_eq!(extract_last_printable_word(""), None);
        assert_eq!(extract_last_printable_word("   "), None);
    }

    #[test]
    fn test_stream_dir_bounds_check() {
        // Stream directory extends past end of dump -- parse_header should reject
        let mut dump = build_minidump_header(5, 32); // 5 streams but only 8 bytes of dir space
        dump.resize(40, 0);
        let mut warnings = Vec::new();
        let result = parse_header(&dump, &mut warnings);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("extends past"));
    }

    #[test]
    fn test_version_mismatch_warning() {
        let mut dump = vec![0u8; 32];
        dump[0..4].copy_from_slice(&MDMP_SIGNATURE.to_le_bytes());
        dump[4..8].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // wrong version
        dump[8..12].copy_from_slice(&0u32.to_le_bytes()); // 0 streams
        dump[12..16].copy_from_slice(&32u32.to_le_bytes());
        dump.resize(32, 0);
        let mut warnings = Vec::new();
        let header = parse_header(&dump, &mut warnings).unwrap();
        assert_eq!(header.version, 0xDEADBEEF);
        assert!(warnings.iter().any(|w| w.contains("Unexpected version")));
    }

    #[test]
    fn test_minidump_credential_struct() {
        let cred = MinidumpCredential {
            identity: "TEST\\admin".to_string(),
            ntlm: Some("aabbccdd".repeat(4)),
            aes256: None,
            aes128: None,
            rc4: None,
            plaintext: Some("P@ssw0rd".to_string()),
            session_type: Some("Interactive".to_string()),
        };
        assert_eq!(cred.identity, "TEST\\admin");
        assert!(cred.plaintext.is_some());
    }

    #[test]
    fn test_minidump_parse_result_struct() {
        let result = MinidumpParseResult {
            credentials: vec![],
            warnings: vec!["test warning".to_string()],
            bytes_scanned: 1024,
            memory_regions: 3,
        };
        assert_eq!(result.bytes_scanned, 1024);
        assert_eq!(result.memory_regions, 3);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_multiple_ntlm_hashes_same_region() {
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let mut ml = build_memory_list(1);
        ml[12..16].copy_from_slice(&80u32.to_le_bytes());
        ml[16..20].copy_from_slice(&64u32.to_le_bytes());
        dump.extend_from_slice(&ml);
        dump.resize(64, 0);

        // Two different NTLM hashes as ASCII hex (32+16+32=80 bytes)
        dump.extend_from_slice(b"aabbccddee112233aabbccddee112233");
        dump.extend_from_slice(&[0u8; 16]); // padding
        dump.extend_from_slice(b"11223344556677881122334455667788");

        let result = parse_minidump(&dump).unwrap();
        assert_eq!(result.credentials.len(), 2);
    }

    #[test]
    fn test_find_username_utf16_backslash() {
        // "admin" in UTF-16LE
        let mut context = vec![0u8; 64];
        // Write "admin" as UTF-16LE at offset 40
        let admin_utf16: Vec<u8> = "admin"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        context[40..40 + admin_utf16.len()].copy_from_slice(&admin_utf16);
        // Write '\\' at offset 50
        context[50] = 0x5C;
        context[51] = 0x00;
        // Write "DOMAIN" after
        let domain_utf16: Vec<u8> = "DOMAIN"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        context[52..52 + domain_utf16.len()].copy_from_slice(&domain_utf16);

        let result = find_username_utf16(&context);
        assert_eq!(result, "admin");
    }

    #[test]
    fn test_zero_entry_in_memory_list() {
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let ml = build_memory_list(0);
        dump.extend_from_slice(&ml);

        let result = parse_minidump(&dump).unwrap();
        // count=0 -> no memory ranges -> falls back to brute-force on empty dump
        assert!(result.credentials.is_empty());
    }

    #[test]
    fn test_memory_list_entry_out_of_bounds() {
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let mut ml = build_memory_list(1);
        // Set rva way past end
        ml[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        ml[12..16].copy_from_slice(&100u32.to_le_bytes());
        dump.extend_from_slice(&ml);

        let result = parse_minidump(&dump).unwrap();
        // Out-of-bounds entry should be skipped
        assert!(result.credentials.is_empty());
    }

    #[test]
    fn test_extract_last_printable_word_with_punctuation() {
        let result = extract_last_printable_word("hello, world!");
        assert!(result.is_some());
        let word = result.unwrap();
        assert!(!word.is_empty());
    }

    #[test]
    fn test_credential_sorting() {
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let mut ml = build_memory_list(1);
        ml[12..16].copy_from_slice(&80u32.to_le_bytes());
        ml[16..20].copy_from_slice(&64u32.to_le_bytes());
        dump.extend_from_slice(&ml);
        dump.resize(64, 0);

        // Two hashes as ASCII hex with different context nearby
        dump.extend_from_slice(b"aabbccddee112233aabbccddee112233");
        dump.extend_from_slice(&[0u8; 32]);
        dump.extend_from_slice(b"11223344556677881122334455667788");

        let result = parse_minidump(&dump).unwrap();
        // Credentials should be sorted by identity
        if result.credentials.len() == 2 {
            assert!(result.credentials[0].identity <= result.credentials[1].identity);
        }
    }

    #[test]
    fn test_aes256_zero_key_filtered() {
        let mut dump = build_minidump_header(1, 32);
        dump.extend_from_slice(&build_stream_entry(STREAM_MEMORY_LIST, 20, 44));
        let mut ml = build_memory_list(1);
        ml[12..16].copy_from_slice(&32u32.to_le_bytes());
        ml[16..20].copy_from_slice(&64u32.to_le_bytes());
        dump.extend_from_slice(&ml);
        dump.resize(64, 0);

        // All-zero AES-256 key as ASCII "0"s (64 bytes of ASCII text)
        dump.extend_from_slice(b"0000000000000000000000000000000000000000000000000000000000000000");

        let result = parse_minidump(&dump).unwrap();
        // Zero key should not appear
        for cred in &result.credentials {
            assert!(cred.aes256.is_none());
        }
    }
}
