# Changelog

## v0.4.4 (2026-08-29)

### WS2022/WS2025 Compliance

- Enhanced NTLM negotiate flags with NEGOTIATE_SIGN, NEGOTIATE_SEAL, NEGOTIATE_128, NEGOTIATE_KEY_EXCH, and NEGOTIATE_56 for WS2025 DC compatibility
- Added NTLM session key derivation in raw LDAP SASL backend for WS2025 LDAP signing enforcement
- Added Kerberos AS-REQ FAST armoring via anonymous PKINIT armor ticket (RFC 6806)
- Added anonymous PKINIT armor TGT support for FAST armoring
- Added hmac_md5 primitive for NTLM session key computation

### DPAPI Remote Extraction

- Implemented DPAPI backup key retrieval via active LDAP session (queries CN=Microsoft,CN=System for PKEY blob)
- Added PKEY blob parser supporting v1/v2 structures (version + GUID + keyMaterial)
- Added remote DPAPI masterkey file reading via SMB from target user profile directories

### UX Improvements

- Improved `ovt exec --method auto` to try all execution methods (SmbExec -> PsExec -> WmiExec) instead of only two
- Replaced `unreachable!()` in DCOM execution path with proper error message
- Added debug logging for auto-exec fallback chain

### Bug Fixes

- Fixed collapsible if clippy warning in DPAPI PKEY parsing
- Fixed constant assertion clippy warning in netlogon_rce test
- Fixed bool assertion clippy warning in timeroast test
- Fixed missing parallel_safe field in qlearner test fixture

## v0.4.3 (2026-08-26)

### Bug Fixes

- SMB2 IOCTL buffer overflow retry now uses full max_transact_size instead of re-capping to 65536
- NTLMv2 identity now uppercases both username AND domain per MS-NLMP section 3.3.2
- SMB signing failures use an atomic counter (threshold of 3) instead of permanently disabling on first failure
- cmd.exe metacharacter escaping now covers %, !, (, ), \r, \n in addition to ^, &, |, <, >, "
- WMIExec output filename includes millisecond timestamp and random ID to prevent collisions
- SASL NTLM bind extracts NetBIOS domain from server challenge target_info (AvId=2) instead of using caller-provided FQDN
- SMB2 directory listing validates NextEntryOffset is forward-progressing and within buffer bounds
- IOCTL STATUS_PENDING retries increased to 7 with exponential backoff for loaded DCs
- LDAP connection timeout increased from 10s to 30s for large forests with Entra Connect
- NTLMv2 MsvAvTargetName fallback chain: AvId=3 (DnsHostName), AvId=1 (NbComputerName), AvId=5 (DnsDomainName)
- SecretsDump boot key extraction tries all ControlSetNNN (001-016) if the active one fails
- SMB negotiate order optimized: tries 3.0.2 first (works on 95% of envs), falls back to 3.1.1
- SMB connect timeout increased from 10s to 15s, now configurable for WAN environments

### New Features

- TUI Wizard (ovt wizard --tui): Interactive click-based module selection with full mouse support
  - 50 modules across 8 categories (Credential, Ticket, Execution, Lateral, PostEx, CVE, Coercion, Enum)
  - Mouse controls: scroll wheel navigation, left-click select, right-click toggle, drag to scroll
  - Target configuration form with editable fields for DC, Domain, Username, Password, NT Hash
  - Live execution log and scrollable results viewer
- CVE-2026-41089 (Netlogon RCE): Unauthenticated RCE via stack-based buffer overflow in MS-NRPC
- CVE-2026-27912 (ResetNightmare): Kerberos password reset privilege escalation via PAC_REQUESTOR_SID bypass
- CVE-2026-33826 (AD RCE): Remote code execution via DRS input validation flaw
- CVE-2026-62818 (AD CS UAF): Use-after-free RCE in Active Directory Certificate Services
- Fallback wordlist updated with 97 passwords (up from 30), including 2026 seasonal patterns and WS2022/WS2025 defaults

### Documentation

- Fixed GOAD-Light references from WS2025 to WS2019 across README, COMMAND_LIST, and POC_REPORT
- Updated COMMAND_LIST.md with TUI Wizard section including keyboard and mouse controls
- Updated README.md with TUI Wizard technique row and quick taste command
- Added v0.4.3 changelog

### Internal

- All 1098+ tests pass, clippy clean across all crates
- New module files: wizard_app.rs, wizard_runner.rs, ad_rce.rs, adcs_uaf.rs, netlogon_rce.rs, resetnightmare.rs
