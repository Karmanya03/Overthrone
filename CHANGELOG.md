# Changelog

## v0.4.8 (2026-09-20)

### SMB shell is now a real smbclient

`ovt smb shell` no longer drops into a `C$`-rooted directory walker. It behaves
like `smbclient //host/share -U user%pass`:

- **Opens directly on a share.** `-s/--share <SHARE>` selects it explicitly; when
  omitted the first readable non-`IPC$` share is chosen and printed. `--path`
  sets the initial remote directory.
- **`-c "ls; get a.txt; exit"`** one-shot mode, matching `smbclient -c`.
- **Full file-management command set**: `ls`/`dir`, `cd`, `pwd`, `lcd`, `lpwd`,
  `get`, `put`, `mget`, `mput`, `more`/`cat`, `del`/`rm`, `mkdir`/`md`,
  `rmdir`/`rd`, `rename`/`mv`, `du`, `stat`/`allinfo`, `shares`, `use`,
  `showconnect`, `reconnect`, `help`, `exit`.
- **`recurse`, `prompt`, `mask`** toggles drive wildcard transfers and `du`
  exactly as they do in smbclient, plus `!<cmd>` for a local shell escape.
- `ls` now prints smbclient's attribute column (`D`/`A` + `H`/`S`/`R`), byte size
  and mtime, because `Smb2Connection::query_directory_detailed()` keeps the
  `SMB2_FILE_DIRECTORY_INFORMATION` timestamps that used to be discarded.
- The interactive REPL's `smb shell` action now enters this same shell with the
  session it already holds instead of printing a "use ovt smb shell" hint.

### SMB2 signing: algorithm auto-detection + diagnostics

Server 2022 (build 20348) and Server 2025 announce AES-128-GCM in the
`SMB2_ENCRYPTION_CAPABILITIES` negotiate context but do not always sign with
AES-GMAC, and the previous code responded by *disabling signature verification*
after three failures -- which silently gave up on integrity instead of fixing it.

- New `SigningVariant` enum models the four real (KDF context, algorithm)
  combinations: `SMBSigningKey`+preauth-hash with CMAC or GMAC, and the 3.0.x
  `SmbSign` context with CMAC or GMAC.
- On the first packet whose signature does not validate, the connection probes
  every candidate against that exact packet and **pins the winner for the rest
  of the session** -- for signing outgoing packets as well as verifying incoming
  ones. Verification is only disabled if *no* candidate validates.
- New `ovt smb sign-diag -t <host>` prints the NTLM exported session key, the
  cumulative 64-byte pre-auth integrity hash, the cipher-predicted variant, the
  detected variant and **every candidate signing key**, so the values can be
  compared byte-for-byte against Impacket/NetExec or Wireshark's SMB2 dissector
  (`KDF_CounterMode(exported_session_key, b"SMBSigningKey\x00", preauth_hash, 128)`).
  This is the capture-comparison workflow the signing investigation needed.

### `ovt smb shares` reports what the server actually advertises

The table was built from a hard-coded list whenever SRVSVC enumeration failed,
which is why a Server 2022 DC answered `3 shares found, 0 readable` -- the three
administrative shares OVT guessed -- while the server advertises five. Both
causes of the enumeration failure are fixed:

- **The signing key derivation.** A 3.1.1 session with no pre-auth hash derived
  its signing key from the `SMBSigningKey` label paired with a `SmbSign`
  context. No implementation derives that pair, so every signed request was
  rejected with `STATUS_ACCESS_DENIED`, the `IPC$` tree connect failed and the
  `srvsvc` enumeration with it. `derive_signing_key` now uses the 3.1.1
  label/context pair or the 3.0.x one, never a mixture.
- **Where the variant is pinned.** It is now pinned from the server's own signed
  `SESSION_SETUP` response, before the first request goes out, and `TREE_CONNECT`
  walks the remaining candidates when the server answers `STATUS_ACCESS_DENIED`
  -- a rejected signature is indistinguishable from a share-permission denial on
  the wire. Probing a candidate logs at debug, so a session that pins correctly
  prints no alarming warnings.

With enumeration working, the table carries only server-reported data:

- New `ShareInfo` holds the SRVSVC `SHARE_INFO_1` the server returned -- name,
  `shi1_type` and `shi1_remark` -- so `ovt smb shares` prints a real `Type`
  (`Disk`/`IPC`/`Print`/`Device`, the label `smbclient -L` uses) and a real
  `Remark` (`Remote Admin`, `Default share`, `Logon server share`, ...), the
  same three columns `netexec smb --shares` prints.
- `Permissions` is `READ,WRITE` / `READ` / `-`, from a real tree connect plus a
  write probe. The probe now deletes the file it creates, so checking a writable
  share no longer leaves `__overthrone_test_*.tmp` behind.
- A row that did not come from an enumeration is marked
  `ShareAccessResult::enumerated == false`, and the CLI says so explicitly: the
  well-known share list is only probed when enumeration is unavailable, and it is
  never presented as the server's own answer.
- **SMB3 encryption is enabled only when the server asks for it.** MS-SMB2 §2.2.6:
  a host with an "encrypt SMB traffic" policy sets `SMB2_SESSION_FLAG_ENCRYPT_DATA`
  in its final `SESSION_SETUP` response, and the session then encrypts with the
  3.1.1 `SMBC2SCipherKey`/`SMBS2CCipherKey` derivations (or the 3.0.x
  `SMB2AESCCM` + `ServerIn `/`ServerOut` contexts). OVT advertised the capability
  but never used it; it now honours the flag and otherwise stays in plaintext,
  like `smbclient` and NetExec.
- Live-verified against the Server 2022 build 20348 DC (`LAINOSCP.local`, SMB
  3.1.1, signing required, AES-128-GCM cipher): five shares enumerated with their
  real types and remarks, and `ADMIN$`/`C$` correctly report no access for a
  non-administrative user -- which the host's own SMB client confirms.

### Priority-3 completeness

- **Removed dead duplicate modules.** `crates/overthrone-cli/src/commands/enum_commands/`
  (`smbclient.rs`, `rpcclient.rs`, `ldap.rs`, `mssql.rs`, ~1,150 lines) was never
  declared in the module tree, so it was not even compiled, while duplicating the
  live implementations in `commands/rpc.rs`, `commands/ldap.rs` and `cmd_mssql`.
  The directory is gone; the maintained implementations are the single source of
  truth.
- **`ovt rpc createdomuser` is no longer a stub.** It now issues
  `SamrCreateUser2InDomain` (opnum 50) for real, parses the returned user handle
  and RID, and then writes the initial password, reporting NTSTATUS on failure.
- **`ovt rpc deletedomuser` is no longer a stub.** It now issues `SamrDeleteUser`
  (opnum 35) against the opened user handle and reports the real status code.
- **`SmbSession::delete_dir` and `SmbSession::rename`** added, backed by a new
  `Smb2Connection::set_file_info()` (SMB2_SET_INFO, `FileRenameInformation`) and
  the `FILE_DELETE_ON_CLOSE` directory-delete path -- these are what smbclient's
  `rmdir` and `rename` use.
- **Wizard `target_hosts` is populated properly.** It used to keep only
  `dnsHostName`, so any computer without a forward record vanished from the
  attack path. It now merges domain controllers discovered through the
  `_ldap._tcp.dc._msdcs.<domain>` SRV records (the DNS equivalent of following
  the LDAP `serverReferenceBL` backlink), falls back to the NetBIOS
  `sAMAccountName` (`DC01$` -> `DC01`, plus the FQDN for DCs), resolves every
  candidate to an address, and de-duplicates the result.

### Tests

- 6 new unit tests for the signing variants, the GMAC nonce (including the
  SIGNED-bit regression), FILETIME/attribute rendering and
  `FILE_RENAME_INFORMATION` layout; 5 new tests for the `smbclient` shell's path
  normalisation, wildcard matcher and tokenizer; 4 new tests for the SAMR
  create/delete builders.
- 1,223 core library tests and 201 CLI tests pass.
- `ovt smb shares` live-tested against a Server 2022 DC, including the
  `SHARE_INFO_1` type/remark parsing and the probed-share marker.

## v0.4.7 (2026-09-17)

### SMB 3.1.1 Signing Fix (critical)

- **AES-GMAC nonce correction**: the SMB 3.1.1 GMAC packet-signing nonce is now
  built exactly as Samba and MS-SMB2 §3.1.4.1 specify -- `MessageId` (8 bytes,
  little-endian) followed by `Flags & SMB2_HDR_FLAG_REDIRECT` (plus
  `SMB2_HDR_FLAG_ASYNC` for SMB2_CANCEL). The previous code embedded the full
  Flags word, including the SIGNED bit (0x08), so every signature Windows
  computed differed from ours and our signed packets were rejected. This broke
  `ovt exec` and every signed SMB 3.1.1 operation against Server 2019/2022/2025.

### LDAP

- **RootDSE base DN auto-correction**: short domain names (e.g. `-d LAINOSCP`) are
  corrected to the real naming context via an authenticated RootDSE probe.
- **Paged-search referral fallback**: a paged search that returns `rc=10` now
  retries without the paging control instead of failing.
- **`ovt ldap search --detailed`**: renamed from `--verbose` to avoid colliding
  with the global `-v` flag.

### New

- **`ovt nxc`**: NetExec-style multi-protocol host triage (smb/ldap/winrm/rpc).

## v0.4.6 (2026-09-10)

### SMB2 Protocol Compliance (WS2019/2022/2025)

- **Session setup body layout fix**: SecurityMode changed from 2-byte `<H` to 1-byte `<B` per Impacket's `SMB2SessionSetup`, matching the actual on-wire format that Windows servers expect. SecurityBufferOffset corrected from 89 to 88 (header 64 + body 24). This was the root cause of `STATUS_INVALID_PARAMETER` (0xC000000D) on session setup.
- **CreditCharge**: Session setup requests now send CreditCharge=1 (matching Impacket default) instead of 0.
- **SPNEGO single-mechanism**: NTLM auth now lists only NTLMSSP in NegTokenInit MechTypes (was listing both NTLMSSP + Kerberos). Multi-mechanism caused server rejection.
- **SMB 3.1.1 re-enabled**: Negotiate now offers all 5 dialects including 3.1.1 (was disabled during debugging).
- **NegotiateContextOffset parsing**: Corrected from body[48] to body[60] for SMB 3.1.1 negotiate responses. NegotiateContextCount corrected from body[52] to body[6]. These offsets match the `SMB2Negotiate_Response` structure in Impacket.

## v0.4.5 (2026-09-02)

### Bug Fixes

- **SMB null session support**: `ovt smb shares --target <IP>` now works without credentials when the target allows null sessions. Uses anonymous NTLM logon when no `-u/-p` provided.
- **S4U impersonation**: Added `--impersonate`, `--altservice`, `--force-forwardable` flags to `ovt kerberos get-tgs` for constrained delegation abuse (S4U2Self + S4U2Proxy flow).
- **PtH auth error messages**: NTSTATUS error codes now mapped to human-readable descriptions (e.g., `STATUS_LOGON_FAILURE (0xC000006D): Invalid username or password`). 35+ error codes mapped.
- **Kerberos ticket auth for exec**: `ovt exec -A ticket` now works instead of returning "not supported". Loads ccache/kirbi and uses Kerberos session setup.
- **WinRM execution**: `--method winrm` now dispatches to the actual WinRM executor instead of falling back to smbexec.
- **MSSQL NT hash auth**: `ovt mssql` now accepts `-A hash` with `--nt-hash` for NTLM hash authentication.
- **LDAP stability**: Added retry logic with exponential backoff (3 retries) for LDAP connection resets and broken pipes.
- **DCSync with ticket auth**: Pilot executor now properly handles ticket-based authentication for DCSync operations.

### New Features

- **TUI Wizard rework**: `ovt wizard --tui` no longer requires credentials at launch. Fill them in the TUI Target Config tab (Tab key) or set via env vars (`OT_DC_HOST`, `OT_DOMAIN`, `OT_USERNAME`, `OT_PASSWORD`). The TUI collects inputs and passes them to module execution.
- **SecLists wordlist auto-discovery**: Commands that need wordlists (kerberoast, asreproast, user-enum, spray) now auto-detect SecLists installation paths. Set `OT_SECLISTS_DIR` for custom location. Checks 15+ common paths across Kali, Parrot, Ubuntu, Arch.
- **`--target-ip` flag for exec**: Bypass DNS resolution with `ovt exec --target DC01.local --target-ip 10.0.0.1`.
- **BloodHound collect subcommand**: `ovt blood-hound collect` subcommand added with `--collection`, `--output-dir`, `--zip` flags.
- **Detailed share permissions**: `ovt smb shares` now shows share type (Admin/Disk/IPC), permission flags, and read/write counts.
- **Wordlist discovery module**: New `wordlist_discovery.rs` in `overthrone-core/src/crypto/` for unified wordlist path resolution.

### Internal

- Added `format_ntstatus()` function mapping 35+ NTSTATUS codes to human-readable messages.
- Added `connect_anonymous()` to SmbSession for null session support.
- Updated `to_exec_context()` to handle Kerberos ticket authentication.
- Pilot executor SMB/LDAP connect now handles ticket auth context.
- All tests pass, build compiles clean.

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
  - 76 modules across 11 categories (Credential, Ticket, Execution, Lateral, PostEx, CVE, Coercion, Enum, AMSI/EDR Bypass, PowerUpSQL, PowerView)
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
