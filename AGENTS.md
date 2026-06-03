# AGENTS Session History

## Build Command
```powershell
cargo build
```

## Test Command
```powershell
cargo test --workspace --lib
```

## Clippy Command
```powershell
cargo clippy --workspace --lib --bins -- -D warnings
```

## Test Counts (as of last run)
- **Total**: 1,206+ tests across 9 crates (+11 strip_mic tests vs previous 1,195)
- **overthrone-core**: 614 (+11 strip_mic tests from 603)
- **overthrone-pilot**: 89
- **overthrone-forge**: 58
- **overthrone-hunter**: 60
- **overthrone-crawler**: 99
- **overthrone-scribe**: 135
- **overthrone-relay**: 78
- **overthrone-reaper**: 48
- **overthrone-viewer**: 25

## Completed Tasks (Honest Account)

### From S-Rank Plan (this session — 11 tasks ticked off)

1. **relay #1 — LDAPS TLS wrapping** (DONE):
   - Added `RelayStreamType` enum (Plain/Tls variant) to `relay.rs`
   - Changed `PendingRelay::stream` and `RelayedSession::stream` from `TcpStream` to `RelayStreamType`
   - Added `ldaps_negotiate_and_challenge` method with TLS wrapping via `crate::tls::wrap_tls()`
   - Split `Protocol::Ldap` and `Protocol::Ldaps` branches in Phase 1
   - LDAPS uses TLS-wrapped stream for Phase 1, reuses it for Phase 2 via the unified type
   - New file: `crates/overthrone-relay/src/tls.rs` (RelayStream, AcceptAllVerifier, build_relay_tls_config)

2. **core #1 — strip_mic_from_type3 tests** (DONE):
   - 11 unit tests covering: flag clearing, MIC bit clearing, MIC zeroing, AV_PAIR preservation, no-MIC, short message, wrong signature, wrong type, non-sign flag preservation, bad offset, multiple AV_PAIRs
   - All pass; no production code changes needed (function was already correct)

3. **cli #2 — Remove unreachable!() calls** (DONE):
   - 3 `unreachable!()` in `main.rs` replaced with proper `eprintln!` + error return
   - 1 `unreachable!()` in `commands_impl.rs` replaced by changing `build_runner_action` return type from `(RunnerForgeAction, HashMap)` to `Result<(RunnerForgeAction, HashMap), String>`
   - 2 remaining `unreachable!()` outside CLI scope (hunter/coerce.rs:323, tools/docgen/src/main.rs:133)

4. **viewer #1 — Refuse non-loopback without TLS** (DONE):
   - Added `bind_address: Option<IpAddr>` field to `ViewerConfig`
   - Validation: `bail!(…)` if non-loopback address + `tls_config` is `None`
   - Default `ViewerConfig::default()` keeps `bind_address = None` (backward compat → resolves to LOCALHOST)

5. **core #2 — Remove dangerous `.unwrap()`** (DONE — reality check: only 1 existed, not ~10):
   - Replaced the single production-code `.unwrap()` in `ldap.rs:2988` (`ntsd[16..20].try_into().unwrap()`) with proper `?` error propagation
   - All `.unwrap()` calls in `pkinit.rs` and `ticket.rs` were already in `#[cfg(test)]` blocks — NOT dangerous, left as-is
   - Also found 3 safe `hex::decode(…).unwrap()` calls in `ntlm.rs` production code (compile-time constants), left as-is

6. **relay #3 — Unicode box-drawing chars → ASCII** (DONE):
   - Replaced across all 10 relay source files:
     - U+2500 (─) → `-`
     - U+2550 (═) → `=`
     - U+2192 (→) → `->`
     - U+2713 (✓) → `[+]`
     - U+2717 (✗) → `[-]`
   - En-dash (U+2013/2014) left as-is (prose characters, not box-drawing)

7. **forge #1 — `run_forge` no longer prints to stdout** (DONE):
   - Removed all `println!` calls from `run_forge()` — no header banner, no result summary, no ticket details
   - Removed `colored::Colorize` import from `runner.rs`
   - Moved ticket-detail display logic to `run_forge_action` in `commands_impl.rs`
   - `run_forge` now purely builds and returns `ForgeResult`; caller decides output format

8. **forge #7 — Validate `payload_path` at config time** (DONE):
   - Added `std::path::Path::new(p).exists()` check in `build_runner_action` for `SkeletonKey`
   - Returns early error message if path doesn't exist, before any network operations

9. **cli #3 — Rename `roast --opsec` → `roast --downgrade-rc4`** (DONE):
   - Field renamed from `opsec: bool` to `downgrade_rc4: bool` in `KerberosAction::Roast`
   - Semantics inverted: `--downgrade-rc4` directly means "downgrade to RC4", matching `downgrade_to_rc4: downgrade_rc4` (was `downgrade_to_rc4: !opsec`)

10. **cli #6 — `--dry-run` for forge** (DONE):
    - Added `dry_run: bool` to `ForgeConfig` struct
    - Added `--dry-run` global CLI flag on `Cli` struct
    - In `run_forge()`, if `config.dry_run` is true, returns immediately with `"[dry-run] Would forge {action} ticket for {user}@{domain}"`
    - Wired in `run_forge_action` via `cli.dry_run`
    - Updated all `ForgeConfig` constructors (runner.rs test helper, skeleton.rs test, modules_ext.rs, interrealm.rs)

11. **cli #7 — JSON output for forge** (DONE):
    - Leveraged existing global `--output-format json` flag and `serde::Serialize` on `ForgeResult`
    - In `run_forge_action`, when `stdout_format == Json`, serializes `ForgeResult` to pretty JSON and prints
    - Also writes to `--outfile` path if set

12. **pilot #6 — Validate wizard config at build time** (DONE):
    - Added `AutoPwnConfig::validate()` method checking: non-empty dc_host, target, domain, username; FQDN format (contains dot); non-empty secret
    - Changed `WizardSession::new()` return type from `Self` to `Result<Self, String>`
    - Updated caller `commands/wizard.rs` to use `map_err(|e| anyhow!(…))?`

13. **scribe #5 — `EngagementSession::new()` findings-population path** (DONE):
    - Changed `auto_generate_findings()` from `fn` to `pub fn` so callers of `new()` (who don't have an `AutoPwnResult`) can populate findings after construction

### From Top-5 Priority List (previous session)

14. **LDAPS TLS Wrapping** (DONE, overlaps relay #1 above)
15. **strip_mic_from_type3 unit tests** (DONE, overlaps core #1 above)
16. **Remove unreachable!() in CLI** (DONE, overlaps cli #2 above)
17. **Viewer non-loopback TLS enforcement** (DONE, overlaps viewer #1 above)

### Heritage (pre-existing completed tasks)

18. **MS-SCMR RPC**: `scmr_exec` in `smb_exec.rs`, `MS_SCMR_UUID` re-exported from `epm.rs`.
19. **Cert Abuse**: `RequestClient`, `ICertPassage`, `RemoteCertService`, ESC1/3/8/11/12 handlers.
20. **LDAP Pagination**: `ldap3` backend handles pagination.
21. **Coercion Trigger**: `trigger_printer_bug`, `trigger_petitpotam`, `trigger_dfs_coerce` in core; TCP wrapper in pilot.
22. **FAST Armoring**: `ArmoredTgsReq`, `PA_PAC_OPTIONS`, `KERB_AD_RESTRICTION_ENC` handling.
23. **AES-Only Kerberoasting**: `kerberoast_ex()` / `request_service_ticket_ex()` with `aes_only` param.
24. **Resource-Based Constrained Delegation**: RBCD module with configure/verify/clear.
25. **DCSync**: `drsuapi.rs` with `DsGetNCChanges` handler.
26. **Hashcat GPU**: `hashcat_gpu.rs`, `which_hashcat()`, CLI `crack --hashcat`.
27. **ESC9/10 WS2025 Fix**: `CertAutoEnroll` for CES enrollment.
28. **Phase 3 Viewer Security**: TLS `TlsListener`, auth/CSRF/CORS middleware.
29. **ViewerConfig Random Credentials**: Random 12-char user, 24-char password, 32-char CSRF.
30. **Phase 5 New Tests**: 40 tests across viewer/relay/forge.
31. **Pre-existing bug fixes**: reaper string escaping, icert_passage stub layout.

## Remaining S-Rank Gaps (Untouched — Brutal Assessment)

These are the items from `technical_debt_and_flaws.md` S-Rank plan that have NOT been started:

### overthrone-core (6 items, ~88h estimated)
- ⬜ **LsaISOHandle / Credential Guard bypass**: Read lsadb.dll via LSAISO handle — requires actual RPC/lsaiso reverse engineering
- ⬜ **Raw syscall via `asm!`**: Replace indirect syscalls with direct `asm!` — cfg-gated, Windows-only
- ⬜ **Azure AD Seamless SSO + Golden SAML**: Full Azure AD Kerberos/SAML integration — 24h, major feature
- ⬜ **Exchange relay targets**: Add Exchange as a relay protocol target
- ⬜ **File-format-aware carver**: Carve secrets from file formats (docx, xlsx, etc.)
- ⬜ **DPAPI masterkey extraction**: Full DPAPI masterkey decryption

### overthrone-relay (5 items, ~52h estimated)
- ⬜ **HTTP→SMB asymmetric relay**: Cross-protocol relay (HTTP auth → SMB)
- ⬜ **IPv6 transport**: Support for IPv6 endpoint connections
- ⬜ **SOCKS5 proxy output**: Route relayed connections through SOCKS5
- ⬜ **DCE/RPC signature stripping**: Strip NTLM signatures from DCE/RPC
- ⬜ **Auto-trigger coercion**: Automatically trigger coerced auth before relay

### overthrone-forge (5 items, ~56h estimated)
- ⬜ **PKINIT-keyed ticket input**: Accept PKINIT client cert as ticket key source
- ⬜ **Top-level ADCS dispatcher**: `cmd_adcs` command routing to ESC handlers
- ⬜ **Raw MS-WCCE COM over RPC**: Direct ICertRequest DCOM activation for remote enrollment
- ⬜ **S4U2Self-with-PKINIT cert chain**: Certificate-based S4U2Self delegation
- ⬜ **AS-REP hash → usable ticket pipeline**: Convert AS-REP hashes into working tickets

### overthrone-cli (4 items, ~44h estimated)
- ⬜ **session_store.rs move to pilot**: Delete from cli, recreate in pilot, wire it up
- ⬜ **Config file loading**: TOML/YAML config file support (CLI args as overrides)
- ⬜ **Profile system**: Named profiles in config file
- ⬜ **Interactive shell mode for forge**: Shell-like REPL for forge operations

### overthrone-hunter (1 item)
- ⬜ **Kerberoast pre-auth check fix**: Wrong flag in pre-auth check (detected in earlier audit)

### overthrone-pilot (1 item)
- ⬜ **Hostile-DC detection**: Detect rogue domain controllers during operations

### overthrone-reaper (all items untouched)
- ⬜ Multiple items not yet scoped

### overthrone-crawler (all items untouched)
- ⬜ Multiple items not yet scoped

### overthrone-scribe (remaining)
- ⬜ Additional report generation enhancements

### overthrone-viewer (remaining)
- ⬜ Additional UI/security hardening

## File Layout
```
crates/
  overthrone-core/src/
    proto/
      kerberos.rs       — kerberoast_ex, request_service_ticket_ex, FAST armoring
      epm.rs            — MS-SCMR re-export, build_rpc_bind/request (pub)
      drsuapi.rs        — DCSync (DsGetNCChanges)
      ntlm.rs           — strip_mic_from_type3 + 11 new tests
      ldap.rs           — DACL offset unwrap → proper error propagation
    exec/
      smb_exec.rs       — WmiExec runner with MS-SCMR as fallback
    crypto/
      cracker.rs        — HashCracker, CrackerConfig::prefer_hashcat
      hashcat_gpu.rs    — Hashcat GPU subprocess (cfg-gated)
  overthrone-relay/src/
    relay.rs            — LDAPS TLS wrapping with RelayStreamType enum, Unicode→ASCII comments
    tls.rs              — RelayStream newtype, AcceptAllVerifier, build_relay_tls_config
    adcs_relay.rs       — Unicode→ASCII cleanup
    exchange.rs         — Unicode→ASCII cleanup
    mitm6.rs            — Unicode→ASCII cleanup
    poisoner.rs         — Unicode→ASCII cleanup
    responder.rs        — Unicode→ASCII cleanup
    smb_daemon.rs       — Unicode→ASCII cleanup
  overthrone-forge/src/
    runner.rs           — ForgeAction enum → run_forge (no stdout), dry_run support
    skeleton.rs         — payload_path validation at config time
  overthrone-hunter/src/
    kerberoast.rs       — KerberoastConfig::downgrade_to_rc4
  overthrone-cli/src/
    main.rs             — 11 ForgeAction variants, --dry-run global flag, --output-format json,
                          --downgrade-rc4 flag (renamed from --opsec), unreachable!() removed
    commands_impl.rs    — build_runner_action returns Result, run_forge_action prints ticket details,
                          JSON output support for forge
    commands/wizard.rs  — WizardSession::new() Result handling
  overthrone-pilot/src/
    runner.rs           — AutoPwnConfig::validate() added
    wizard.rs           — WizardSession::new() returns Result<Self, String>
  overthrone-scribe/src/
    session.rs          — auto_generate_findings() made public
  overthrone-viewer/src/
    server.rs           — ViewerConfig::bind_address, non-loopback+TLS validation
```
