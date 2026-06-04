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
- **Total**: 1,474 tests across 9 crates (all pass)
- **overthrone-core**: 614
- **overthrone-pilot**: 110
- **overthrone-forge**: 58
- **overthrone-hunter**: 66 (+6 preauth tests)
- **overthrone-crawler**: 89
- **overthrone-reaper**: 135
- **overthrone-relay**: 73
- **overthrone-scribe**: 48
- **overthrone-viewer**: 25
- **overthrone-cli bin**: 128 (+14 profile tests in cli_config, +31 profile subcommand tests in commands::config, +25 cli_config tests, +14 commands::config tests, +2 wizard arg tests, +12 session tests inside)

## Completed Tasks (Honest Account)

### From S-Rank Plan (this session — 13 tasks ticked off)

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

14. **reaper #1 — BH edge-type coverage** (DONE):
    - Added 19 new `EdgeType` variants to `crates/overthrone-core/src/graph/mod.rs`:
      `AllExtendedRights`, `CreateChild`, `WriteSelf`, `ReadLapsPasswordExpiry`,
      `WriteSPN`, `WriteKeyCredentialLink`, `AddKeyCredentialLink`,
      `WriteAllowedToDelegateTo`, `AddAllowedToAct`, `WriteAccountRestrictions`,
      `Enroll`, `EnrollOnBehalfOf`, `ManageCA`, `ManageCertificates`, `ManageCertTemplate`
    - Updated `default_cost()` for new variants
    - Updated `from_str_name()` mapping with `AddMember` aliased to `AddMembers`
    - Updated `edge_color()`, `edge_severity()`, `edge_ovt_command()`, `edge_operator_note()`
      in `crates/overthrone-cli/src/tui/graph_view.rs`
    - Viewer `edge_security_guidance()` already handled string-based matches
    - Full workspace clippy clean, 1212 tests all pass

15. **pilot+cli #6/#1 — Wire session management CLI** (DONE):
    - **Reality check**: doc said `cli/session_store.rs` was orphaned dead code, but
      that file doesn't exist. The real situation: `overthrone_pilot::session` already
      exists (save_session/load_session/auto_session_path) and `cli/autopwn.rs` calls
      `save_session` — but `load_session` was only used by tests. There was no way
      for the operator to actually resume a saved engagement from the CLI.
    - **New `ovt session` subcommand** with 7 actions:
      `list`, `show <name>`, `info <name>`, `delete <name>`, `clean --older-than <Nd|Nh|Nm>`,
      `path <name>`, `stats`. Aliased as `ovt sessions`.
    - 12 unit tests covering age parsing, byte/duration formatting, save/load roundtrip,
      dir listing, non-JSON file filtering
    - **Wired `--from-session <name>` to wizard** — loads saved `EngagementState`,
      skips Enumerate if the state already has users/computers/groups, runs Attack→Cleanup
    - New `WizardSession::new_with_state(config, checkpoint_dir, state)` constructor in
      `crates/overthrone-pilot/src/wizard.rs` (skips Enumerate when state has data)
    - `discover`ed existing session: smoke-tested `ovt session list/show/path/stats` against
      real `~/.overthrone/sessions/corp.local-1.1.1.1.json` — works end-to-end
    - All 1262 tests pass, clippy `-D warnings` clean

16. **hunter #2 — Kerberoast pre-auth check test coverage** (DONE):
    - **Reality check**: doc claimed the check at `kerberoast.rs:158` uses the "wrong flag".
      Verified: `AdUser.dont_req_preauth` is populated by `parse_ad_user` from
      `uac & UAC_DONT_REQ_PREAUTH` (0x400000 = 4194304 = UF_DONT_REQUIRE_PREAUTH).
      The check IS on the right bit.
    - **Real fix**: added 6 unit tests that pin the UAC bit value, prove the
      `parse_ad_user` logic works on edge cases (normal, disabled+preauth, no-preauth),
      verify the rust-side filter logic with a mock user set, and confirm the
      default `KerberoastConfig` has `skip_asrep_roastable=true`.
    - Negative test: ensures no other UAC bit collides with `0x400000`
      (no false positives on UF_DONT_EXPIRE_PASSWD, UF_TRUSTED_FOR_DELEGATION, etc.)
    - Result: hunter tests 60 → 66

### From Top-5 Priority List (previous session)

14. **LDAPS TLS Wrapping** (DONE, overlaps relay #1 above)
15. **strip_mic_from_type3 unit tests** (DONE, overlaps core #1 above)
16. **Remove unreachable!() in CLI** (DONE, overlaps cli #2 above)
17. **Viewer non-loopback TLS enforcement** (DONE, overlaps viewer #1 above)

17a. **cli #3 — TOML config file loading** (DONE):
   - Expanded `crates/overthrone-cli/src/cli_config.rs` from 68 → 470 lines:
     `CliConfig` struct (17 fields, `Serialize`/`Deserialize`), `save_config()`,
     `default_config_path()` (XDG-aware), `set_value()` + `unset_value()` with
     per-key validation, `display()` (masks secrets: password/nt_hash/pkinit_key
     show `hu********et`-style), `compact()`, `CONFIG_KEYS` registry
   - 25 new unit tests: parse_minimal/parse_full/parse_unknown_keys_ignored,
     save_then_load_roundtrip, save_creates_parent_dir, set/unset value,
     validation of auth_method/stdout_format/verbose/bool parsing,
     display masks secrets, mask_secret short strings, default_config_path
   - Fixed missing `auth_method` and `user_list`/`pass_list`/`user_pass_list`
     fields in main.rs inline merge (had been silently dropped from config)
   - Added `FromStr for AuthMethod` (was missing — blocked the merge)
   - New `crates/overthrone-cli/src/commands/config.rs` (440 lines) with
     `ovt config` subcommand + 7 actions: `init [--force]`, `show`, `path`,
     `set <KEY> <VALUE>`, `unset <KEY>`, `edit` ($EDITOR launcher),
     `save`. Aliased as `ovt cfg`
   - 14 new tests in `commands::config`: init_refuses_overwrite, init_force,
     set/unset roundtrip on disk, show_handles_missing/existing, edit env
     fallback, edit_creates_file_if_missing, save_writes_default,
     config_keys_match_enum_variants_in_set, set_value_writes_pretty_toml,
     show_masks_password, set_then_show_round_trip
   - All 1384 test runs pass; clippy `-D warnings` clean

17b. **cli #4 — Profile system** (DONE):
   - Named profiles stored at `<config_dir>/profiles/<NAME>.toml`,
     honor `OT_CONFIG` env var
   - Added to `cli_config.rs` (~150 lines): `default_profiles_dir()`,
     `profile_path(name)`, `validate_profile_name()` (rejects path
     traversal, > 64 chars, control chars), `load_profile()`,
     `save_profile()`, `delete_profile()`, `list_profiles()`,
     `profile_exists()`, `clone_profile()`, `active_profile()` (reads
     `OT_PROFILE` env)
   - 14 new unit tests: name validation (accept/reject/path-traversal/
     too-long/invalid-chars), profile path is under profiles dir,
     profile_path rejects invalid names, save/load roundtrip,
     load_profile returns default when missing, active_profile reads
     env var, list_profiles empty dir, delete_profile rejects missing,
     profile_exists rejects invalid, clone_profile roundtrip
   - Added `--profile <NAME>` global flag on `Cli` (env: `OT_PROFILE`)
   - Refactored config merge in `main.rs` to extract
     `apply_config_layer()` helper; precedence is now:
     CLI flag > env > active profile > main config > default
   - Added `ovt config profile` subcommand (7 actions): `list`, `show`,
     `create [--force]`, `set <NAME> <KEY> <VALUE>`, `unset <NAME>
     <KEY>`, `delete [--yes]`, `use`, `clone <SRC> <DST>`, `path`
   - 31 new tests in `commands::config` (profile_create_refuse/
     force/rejects_invalid_name, profile_list, profile_show_missing/
     existing/requires_name, profile_delete_missing/removes_existing,
     profile_use_prints/warns, profile_clone_copies/rejects_existing/
     rejects_invalid, profile_path_resolvable/requires_env, profile_set
     _creates/replaces/rejects_unknown_key/validates_auth_method/
     validates_stdout_format/parses_bool/parses_verbose, profile_unset
     _clears/rejects_unknown/errors_when_missing/handles_all_field_types,
     profile_action_dispatch_handles_all_variants, profile_path_for
     _rejects_invalid, current_profiles_dir_is_under_config_dir)
   - All 1474 tests pass; clippy `-D warnings` clean
   - Smoke tested end-to-end: created profile, set multiple key types
     (string, bool, u8, auth_method, stdout_format), listed, showed,
     used, unset, deleted — all correct

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

### overthrone-cli (2 items, ~28h estimated)
- ✅ ~~**session_store.rs move to pilot**~~ (DONE — task 15)
- ✅ ~~**Config file loading**~~ (DONE — task 17a, TOML only, no YAML)
- ✅ ~~**Profile system**~~ (DONE — task 17b, named profiles at `<config_dir>/profiles/<NAME>.toml`)
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
    graph/
      mod.rs            — EdgeType expanded with 19 BH-compatible variants, default_cost, from_str_name
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
                          --downgrade-rc4 flag (renamed from --opsec), unreachable!() removed,
                          +Session subcommand (list/show/delete/clean/path/stats/info),
                          +Config subcommand dispatch
    cli_config.rs       — CliConfig struct (17 fields, Serialize/Deserialize),
                          save_config/set_value/unset_value/display with secret masking,
                          default_config_path (XDG-aware), CONFIG_KEYS registry, 39 unit tests
                          + profile system: load/save/delete/list/clone/validate,
                          default_profiles_dir, active_profile, OT_CONFIG/OT_PROFILE env support
    commands_impl.rs    — build_runner_action returns Result, run_forge_action prints ticket details,
                          JSON output support for forge
    commands/config.rs  — NEW: ConfigArgs/ConfigAction (init/show/path/set/unset/edit/save
                          + profile subcommand with 7 actions: list/show/create/set/unset/delete/use/clone/path),
                          aliased as `ovt cfg`, 45 unit tests
    commands/session.rs — SessionArgs/SessionAction, 12 unit tests
    commands/wizard.rs  — WizardSession::new() Result handling, --from-session <NAME> resume path
    auth.rs             — FromStr for AuthMethod (was missing), PartialEq added
    tui/
      graph_view.rs     — edge_color, edge_severity, edge_ovt_command, edge_operator_note updated
  overthrone-pilot/src/
    runner.rs           — AutoPwnConfig::validate() added
    session.rs          — save_session, load_session, auto_session_path, session_path (was pre-existing)
    wizard.rs           — WizardSession::new() returns Result<Self, String>,
                          +new_with_state() constructor for pre-populated EngagementState
  overthrone-hunter/src/
    kerberoast.rs       — KerberoastConfig::downgrade_to_rc4, +6 preauth UAC bit tests
  overthrone-scribe/src/
    session.rs          — auto_generate_findings() made public
  overthrone-viewer/src/
    server.rs           — ViewerConfig::bind_address, non-loopback+TLS validation, edge_security_guidance
```
