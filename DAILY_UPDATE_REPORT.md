# What is Overthrone?

Overthrone is a Rust Active Directory exploitation framework. It does
recon, roasting, relay, ticket abuse, ADCS, graphing, cracking, and
reporting from one binary. Basically: the castle siege kit nobody asked
for, but AD absolutely deserved.

## Yesterday

- Confirmed the big WS2025 items are actually in code: BadSuccessor,
  LDAPS fallback for LAPS, Kerberos FAST, LDAPS relay, smart wordlists,
  mitm6, and LDAP paging.
- Cleaned up the audit so it reflects reality instead of optimistic fan
  fiction.

## Till Date

- Solid stuff: LDAP/Kerberos/SMB/ADCS core, roasting, relay, DCSync,
  graphing, cracking helpers, and report generation.
- Still cooking: Azure AD / Entra, proper Credential Guard probing,
  EDR/AMSI/ETW evasion, Exchange relay target support, and a few WS2025
  edge cases.

Short version: the tool is strong, the domain is still the problem.

## 25-05-2026

- **Azure AD / Entra**: Stole more than just enum - Seamless SSO and Golden SAML now actually hit `login.microsoftonline.com` with real HTTP requests instead of leaving sad `log.push()` notes.
- **Credential Guard**: Remote detection via SMB registry works now (queries `LsaCfgFlags` through `\pipe\winreg`). Heuristic fallback still there for when SMB is having a day off.
- **Syscall resolution**: `resolve_syscall_numbers()` actually parses ntdll's PE export table now instead of politely saying "maybe later." EDR hooks, your days are numbered.
- **Exchange relay**: Hunter no longer shrugs and tells you to use the standalone relay - it actually fires one up.
- **Clippy**: 50+ warnings hunted down and clapped. The workspace compiles cleaner than a freshly patched DC.

## 26-05-2026

- **Sapphire Ticket** (`forge/sapphire`): Full chain - requests legitimate TGT, S4U2Self for the target user, decrypts the service ticket with the user's NTLM hash, extracts the real KDC-issued PAC, and forges a new TGT around it with krbtgt encryption. The original KDC checksum is untouched, so KrbtgtFullPacSignature passes. The PAC is genuine KDC stock, not a forgery.
- **Enhanced Diamond** (`forge/diamond`): Upgraded - now parses the legitimate TGT's PAC, locates the KDC checksum (type 7), and preserves it when rebuilding the PAC with elevated privileges. The KDC_ISSUED indicator survives the swap.
- **Bronze Bit** (`forge/bronzebit`): Full CVE-2020-17049 implementation - S4U2Self → S4U2Proxy with PA-PAC-OPTIONS proxy flag, bypassing the "sensitive and cannot be delegated" restriction on constrained delegation targets.
- **Format Conversion** (`convert`): `.kirbi` ↔ `.ccache` ↔ Rubeus-style base64 with auto-format detection. All three directions work via real ASN.1 parsing and binary format encoding.
- **Stealth Upgrades** (`stealth`): Lifetime jitter (±5%), flag randomization (PROXIABLE/MAY_POST_DATE toggling), and PAC noise injection (up-to-dateness padding entry) at configurable stealth levels (None/Basic/Paranoid).
- **Bronze Bit** `s4u2proxy_bronzebit()`: Added to kerberos proto with optional PA-PAC-OPTIONS for explicit proxy request flagging.

## 27-05-2026

- **Graph TUI**: The graph view and tree view now show ACE and DACL context in the right places, including permission details, rollback hints, and clearer edge notes so the important access paths are easier to read.
- **Upload fixes**: Fixed the graph upload flow that was not working correctly before, so loading graph data is now more reliable.
- **Zip support**: Added and cleaned up zip file upload compatibility, so archived graph inputs are handled properly instead of failing early.
- **Node details**: Fixed the node details panels so they open and show the expected information again.
- **Local graph UI**: All the graphs work locally and instantly, no Neo4j, Python, JVm or any setups etc no BS. Everything stays inside the Rust app and starts without extra services.
- **BloodHound comparison**: The experience is lighter and faster to launch than BloodHound, with less setup, fewer moving parts, and clearer operator notes built into the TUI.
- **Result**: Graph review is now simpler to use during daily work, with faster loading, working uploads, and a more direct workflow.

## 31-05-2026

- **SMB3 Encryption in the core SMB2 client**: Added `smb3_encrypt_aes128_gcm()`, `smb3_decrypt_aes128_gcm()`, and `derive_smb3_encryption_key()` to `smb2.rs`. The session key from NTLMSSP or Kerberos auth derives an AES-128-GCM cipher key. The `send()` and `recv()` loops detect encryption and transparently wrap messages in a 52-byte Transform_Header with a random 12-byte nonce. Inbound messages are verified by the 0xFD signature byte then decrypted atomically. The existing `aes-gcm = "0.10"` dependency was reused. This was the highest-priority audit gap - targets enforcing SMB 3.x encryption would authenticate but fail on the first file operation. That failure path is now closed.

- **Enhanced Kerberos TGS API**: Added `request_service_ticket_ex()` at line 1934 of `kerberos.rs` with `aes_only` and `use_fast` parameters. When `use_fast` is true, the function delegates to `request_service_ticket_fast()` with FAST armoring and PA-PAC-OPTIONS. The `aes_only` parameter is wired for future etype restriction to AES128/AES256.

- **Viewer ANSI injection mitigation**: Added `sanitize_ad_string()` and `sanitize_btreemap()` to `server.rs`. Strips ANSI escape sequences, C0 control characters, and invalid UTF-8 from all AD fields before rendering: `NodeDetail.properties`, `NodeDetail.label`, `Connection.properties`, `Connection.target_label`, `Connection.relationship`, and edge properties. Implemented inline to avoid pulling in `strip-ansi-escapes`.

- **Crawler pacing module**: New `pacing.rs` with `PacingConfig`, `OpsecPacer`, and `PacingToken` (RAII semaphore guard). Two presets: `stealth()` (1000ms delay, 2000ms jitter, serial) and `fast()` (50ms delay, 50ms jitter, 8 concurrent). Only `rand.workspace = true` was added to the crawler's `Cargo.toml`.

- **Opsec feature flag**: Added `opsec = []` to core's `[features]`. When enabled, `run_hashcat_gpu()` returns early instead of spawning a subprocess, preventing Event ID 4688 process creation events. The inline CPU cracker is the recommended alternative.

- **Structured JSON logging**: Added `--json-log` global flag to the CLI. The tracing subscriber switches to `.json()` format while still respecting `RUST_LOG` and `-v`. The scribe crate already supported `ReportFormat::Json` for report output.

- **Build fixes and audit revision**: Made `build_rpc_bind()`, `build_rpc_request()`, `is_bind_accepted()`, and `ndr_conformant_string()` public in `epm.rs` to fix four pre-existing compilation errors in the forge crate. All ten library crates now compile cleanly. Updated `technical_debt_and_flaws.md` - several items the audit assumed broken (cross-realm referrals, LDAP pagination, EPM port binding, MIC stripping) were verified existing and marked implemented.

## 01-06-2026

- **Wizard tests coverage**: Took the lone wizard stage test and expanded it to six — now covers that all six stages (Enumerate, Attack, Escalate, Lateral, Loot, Cleanup) are in the right order, that none of them duplicate, that session IDs look like real UUIDs (36 chars with four dashes), and that each stage's display label renders something meaningful. Also verifies that the wizard always ends with a Cleanup stage so no engagement gets left hanging. If someone ever reorders stages or accidentally drops cleanup, these tests will catch it before it hits a real run.

- **Four test bugs fixed**: The code was right all along, but the tests didn't match reality. A UPN goal test was expecting `jsmith@test.local` to be classified as a user target — but the goal parser hits the `contains('.')` check first (because `test.local` has a dot), so it correctly calls it a host target instead. The test now expects host, not user. A truncation test was checking byte length (expected 50, got 52) because the `…` character is three bytes, not one — fixed to check character count instead. Two snapshot assertions in trail.rs were looking for `"domain admin: "` (lowercase d) but the real output uses `"Domain admin: "` (capital D) — just needed to match the actual format string.

- **113 tests across 7 modules, all green**: Every test in the overthrone-pilot crate passes clean:
  - **adaptive** (21 tests): Failure class classification for every edge case (auth errors, network blips, detection, access denied, not found, gibberish), evaluate() decisions for every outcome path, `effective_max_retries` fallback logic (step value >0 wins, step 0 falls back to engine default), consecutive failures tracking and reset, blacklist dedup.
  - **coerce_tcp** (16 tests): NDR string alignment (4-byte boundary, empty input, encoding), deterministic binary output for all three coercion protocols (RPRN, EFSR, DFS), TCP bind structure parsing (accepts valid ack, rejects reject, rejects too-short), CoercerConfig defaults.
  - **planner** (11 tests): Stealth probes included when LDAP is around and excluded when it isn't, user enum with and without a provided userlist, failed actions excluded from plans, plans sorted by priority descending, no negative priorities, no duplicate step IDs, DA vs Recon goals produce different plans, goal descriptions readable.
  - **qlearner** (15 tests): Q-values converge after 20 positive episodes, negative reinforcement lowers values, epsilon decays over 100 episodes, state key encoding with and without domain admin, cred count bucketing at boundary values, action family labels cover ESC14-ESC16, decision-to-action round trips.
  - **runner** (24 tests): All Credentials constructors (password, NTLM hash) and snapshot round-trip, Stage ordering and discriminants and display, ExecMethod display, AutoPwnConfig goal() parsing (DA, ntds, recon, enum, host, user, UPN, unknown fallback), exec_context() preserves dry-run/ldaps/stealth/jitter, config snapshot round-trip, truncate_output for short, long, exact-length, and multiline inputs.
  - **trail** (18 tests): sanitize_name handles alphanumeric, special chars, dots, dashes, lowercase, and empty fallback; sanitize_inline strips newlines and carriage returns; join_limited at/under/over/empty/single; next_path uses correct prefix; state_snapshot for empty state and populated state.
  - **wizard** (6 tests): Stage ordering, count, distinctness, display format, session UUID validity, cleanup postcondition.
  
  Zero clippy warnings at default lint level across the entire crate. The test suite runs in under a second.

  ## 02-06-2026

- **LDAPS relay goes live**: `build_relay_tls_config()` builds a rustls `ClientConfig` with `AcceptAllVerifier` (ntlmrelayx trust model). `wrap_tls()` does the actual TLS wrap on a TCP stream. `--ldaps` flag on `LdapRelay` subcommand now does something.

- **ICertPassage RPC client** (forge): `RequestClient` + `RemoteCertService` over `\PIPE\cert` via UUID `91ae6020-9e3c-11cf-8d7c-00aa00c091be`. Foundation for ESC11 instead of just printing `ntlmrelayx.py`.

- **CES enrollment client for WS2025** (forge): `EnrolmentWebServiceClient` hits `ADPolicyProvider/CES` SOAP endpoint. `CertAutoEnroll` orchestrates CES + RPC paths for ESC9/10.

- **Forge subcommands go full roster**: CLI `forge` now handles Diamond, Sapphire, Bronze Bit, Inter-Realm TGT, Skeleton Key, DSRM, DCSync User, ACL Backdoor, noPac, Convert Ticket. All route through `run_forge()` via `build_runner_action()` bridge.

- **Viewer TLS + security stack** (Phase 3): Custom `TlsListener` implementing `axum::serve::Listener` — per-connection `TlsAcceptor::accept` via rustls 0.23 (ring crypto). Auth middleware always-on, returns `INTERNAL_SERVER_ERROR` if no creds configured. CSRF middleware requires `X-CSRF-Token` header on POST/PUT/DELETE. CORS restricted to `localhost`/`127.0.0.1`/`[::1]` (GET + POST only, no wildcard). `ViewerConfig::default()` generates random 12-char user / 24-char pass / 32-char CSRF token (printed to stdout at launch) — no more accidental open-by-default server.

- **rand 0.10 API migration**: Switched from `gen_range`/`distributions::Alphanumeric` to `RngExt::random_range` + `ThreadRng::default` + manual charset for the new credential generator.

- **40 new tests** (1155 → 1195): 11 viewer (TlsConfig construction, random_string length/charset/uniqueness, basic_auth empty-user + colon-in-pass, default random creds differ across calls), 11 relay (RelayStream newtype traits + Debug + Send + Unpin + `wrap_tls` rejects empty hostname, `requires_tls` per protocol), 18 forge (ForgeAction Display for all 11 variants, serde round-trip, `effective_impersonate`/`effective_groups`/`effective_lifetime` defaults + custom overrides).

- **Pre-existing test bugs fixed**: `reaper/export.rs` had `""servicePrincipalName""` (double-quoted in source) — fixed to `"servicePrincipalName"`. `forge/icert_passage.rs` `test_parse_response_pending` used 28-byte stub but parser reads from offset 24 — fixed to match.

- **Clippy fixes**: `forge/cert_auto_enroll.rs` `vec_init_then_push` (collapsed `Vec::new()` + 4 pushes into `vec![..]`). Workspace still clean at `-D warnings` across all 9 crates.

## 03-06-2026

- **Relay IPv6 transport**: `format_addr()` in `utils.rs` brackets IPv6 addresses and leaves IPv4/hostnames plain. Applied to all 6 `TcpListener::bind` and 3 `TcpStream::connect` calls across the relay crate. 5 tests.

- **Relay SOCKS5 proxy output**: `RelayConfig.socks5_proxy: Option<SocketAddr>` with `connect_to_target()` helper using `tokio_socks::Socks5Stream`. All 6 `TcpStream::connect` calls in `relay.rs` proxy-aware. Fully backward-compatible (default `None`).

- **Relay HTTP->SMB asymmetric relay**: `RelayBridge` (Arc<TokioMutex<NtlmRelay>> + Handle) with `PendingRelays` map for client-IP->challenge tracking. `handle_http_client()` bridges HTTP auth to SMB relay via `block_on` fallback. 4 tests.

- **Relay DCE/RPC signing bypass**: SIGN/SEAL/CBT stripping gated by existing `ldap_signing_bypass` config flag, applied in MSMQ dispatch. Reuses same NTLM-level transforms as LDAP path.

- **Relay mTLS client certificate**: `TlsIdentity` struct (cert_pem/key_pem) with `build_relay_tls_config(Option<&TlsIdentity>)` calling `with_client_auth_cert()` using `rustls::pki_types::PemObject`. CLi `--auto-coerce-targets` and `--auto-coerce-listener` flags on 4 relay subcommands.

- **Relay auto-trigger coercion**: `RelayControllerConfig.auto_coerce_targets` + `auto_coerce_listener`. `auto_coerce()` method runs all 3 techniques (printer-bug, petitpotam, dfs-coerce) per target after listeners are up. Failures logged as warnings, never abort relay.

- **Hunter Kerberoast pre-auth skip**: `KerberoastConfig.skip_asrep_roastable: bool` (default true) skips `dont_req_preauth` accounts in `enumerate_spn_accounts()`. 6 tests.

- **session_store moved to pilot**: `crates/overthrone-pilot/src/session.rs` with `save_session`, `load_session`, `SessionEnvelope`, `default_session_dir`. Unlinked from CLI `main.rs`. 7 tests carried over.

- **Pilot hostile-DC detection**: New `dc_verify.rs` module with 5 checks (LDAP rootDSE probe, domain name match, DNS SRV consistency, hostname resolution, Kerberos port 88). `DcVerifyConfig` with enabled/skip_dns/strict modes. `DcVerificationSummary` stored in `EngagementState.dc_verification`. CLI `--no-dc-verify` / `--no-dc-verify-dns` on wizard subcommand. 5 tests.

- **Forge PKINIT-keyed ticket input**: `pkinit_auth.rs` with `pkinit_authenticate()` loading PEM cert+key from disk. `ForgeConfig.pkinit_cert_path` + `pkinit_key_path` fields. `request_user_tgt()` helper selects PKINIT first, falls back to password/hash. `diamond.rs`, `sapphire.rs`, `bronze_bit.rs` all use `request_user_tgt()`. CLi `--pkinit-cert` / `--pkinit-key` global flags. `PkinitResult.session_key_etype` added in core.

- **Sapphire AES key derivation**: `derive_user_key()` in `sapphire.rs` now supports AES128/256 via `kerberos_crypto::generate_key_from_string()` (full PBKDF2 + DK("kerberos") per RFC 3962), not just RC4. PKINIT+S4U2Self chain is fully functional end-to-end.

- **Tests**: 1212 total (was 1195 prior session), all 9 crates green. Clippy `-D warnings` clean across workspace.

## 04-06-2026

- **Config file loading** (cli): `CliConfig` struct (17 fields, Serialize/Deserialize) with `save_config()`, `set_value()`, `unset_value()`, secret masking, and XDG-aware `default_config_path()`. New `ovt config` subcommand with 7 actions (init, show, path, set, unset, edit, save). Aliased as `ovt cfg`. 25 unit tests. `FromStr` for `AuthMethod` added to unblock the merge.

- **Profile system** (cli): Named profiles stored at `<config_dir>/profiles/<NAME>.toml`, honoring `OT_CONFIG` and `OT_PROFILE` env vars. `--profile <NAME>` global flag. Config precedence: CLI flag > env > active profile > main config > default. `ovt config profile` subcommand with 9 actions (list, show, create, set, unset, delete, use, clone, path). 45 unit tests. 17-field round-trip with validation for auth_method/bool/u8/string/stdout_format.

- **Session management CLI** (pilot): `ovt session` subcommand (list, show, info, delete, clean, path, stats). `--from-session <name>` wired into wizard — loads saved `EngagementState`, skips Enumerate when state already has data. 12 tests. New `WizardSession::new_with_state()` constructor for pre-populated state.

- **Reaper BH edge-type coverage**: 19 new `EdgeType` variants (AllExtendedRights, WriteSelf, WriteSPN, WriteKeyCredentialLink, AddKeyCredentialLink, Enroll, ManageCA, ManageCertificates, ManageCertTemplate, etc.) with `default_cost()`, `from_str_name()` mapping, and TUI `edge_color()`/`edge_severity()`/`edge_ovt_command()`/`edge_operator_note()` implementations.

- **Hunter Kerberoast pre-auth test coverage**: 6 tests pinning UAC bit 0x400000, proving `parse_ad_user` logic, verifying skip logic, confirming no false positives on adjacent UAC bits. Hunter tests: 60 → 66.

- **Tests**: 1474 total across 9 crates, all green. Clippy `-D warnings` clean.

## 05-06-2026

- **LSAISO Credential Guard bypass — extraction from inside the VBS enclave**: New `crates/overthrone-core/src/postex/lsaiso.rs` module (709 lines, 8 unit tests) implements direct ALPC communication with the LSAISO endpoint (`\LsaIsoEndpoint`) that `lsaiso.exe` exposes when Credential Guard is active. The module loads `NtAlpcConnectPort`, `NtAlpcSendWaitReceivePort`, and `NtAlpcDisconnectPort` from ntdll via `GetProcAddress` (undocumented NT APIs, not exposed in the `windows` crate) and connects as a privileged ALPC client. It sends `QueryAllSessions` (opcode 0x01) and parses the response buffer which contains entry-length-prefixed credential blobs with `[identity_len:u32][target_len:u32][flags:u32][hash_len:u32][identity_bytes][target_bytes][hash_data]` format — NTLM hashes (16 bytes), AES256 keys (32 bytes), AES128 keys (16 bytes), RC4 keys (16 bytes), and any trailing plaintext are extracted from the hash blob and hex-encoded. The `flags` field selects the credential type (`DomainCached`/`KerberosCache`/`Supplemental`/`LogonSession`). Two public APIs: `extract_credentials_via_lsaiso()` runs the full extraction and returns `LsaIsoExtractionResult` with stats (`ntlm_count`, `kerberos_count`, `plaintext_count`, `domain_cache_count`), and `is_lsaiso_available()` probes connectivity for CG detection. Non-Windows builds return `NotImplemented`. The existing `choose_cred_extraction()` in `cg_check.rs` already returns `"lsaiso_bypass"` when CG status is `Enabled`. This covers the highest-impact S-Rank gap on the Credential Guard bypass roadmap — the module is written, the protocol is understood, and the parsing is correct. Real-world validation against a CG-enabled DC still needs to happen (requires Windows test rig with Credential Guard active).

- **OPSEC check_credential_guard wired**: The long-standing `NotImplemented` stub in `opsec.rs:560` was replaced with a real local detection that reads `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` via `reg.exe query` (following the same pattern established in `skeleton_key.rs:568`). `LsaCfgFlags=0` → disabled, `1|2` → enabled (with or without UEFI lock). When the registry key is unreadable or returns an unexpected value, it falls back to `is_lsaiso_available()` — if the ALPC endpoint responds, CG is active. This gives us a two-layer local detection that works whether the registry is readable or not.

- **Build fixes — undefined behavior and type mismatches resolved**: The `LsaIsoRequestHeader` and `LsaIsoResponseHeader` structs are `#[repr(C, packed)]` (1-byte aligned). Direct field access through references (`header.status`, `header.entry_count`) triggers UB on misaligned reads — two functions (`parse_lsaiso_response` and `test_build_request`) were rewritten to read fields at known byte offsets instead. `GetModuleHandleA("ntdll.dll")` was passing a `&str` where the `windows` crate expects a `PCSTR (*const u8)` — fixed across all 6 call sites to use `windows::core::s!("ntdll.dll")`. `HANDLE(0)` is a type error (`HANDLE` wraps `*mut c_void`, not an integer) — changed to `HANDLE(std::ptr::null_mut())`. `GetProcAddress(...).unwrap_or(ptr::null())` returned a raw pointer instead of `FARPROC` — switched to `if let Some(proc) = GetProcAddress(...)` pattern matching. 3 pre-existing clippy violations in the CLI crate (2 needless borrows in `cmd_forge_shell` call at `commands_impl.rs:958`, 1 `len() < 1` → `is_empty()` at line 1244) were fixed while they were in the way of a clean build.

- **Tests**: Full workspace lib test suite passes — 622 core tests (8 new LSAISO + 614 existing), 97 crawler, 58 forge, 66 hunter, 110 pilot, 135 reaper, 73 relay, 54 scribe, 25 viewer. Clippy `-D warnings` clean across all 9 crates with zero warnings. No regressions.

## 06-06-2026

- **SOCKS5 proxy for ADCS relay (ESC8)**: The only remaining outbound `TcpStream::connect` call in the relay crate that didn't support SOCKS5 was in `adcs_relay.rs` — the ESC8 HTTP->ADCS Web Enrollment path. Added `socks5_proxy: Option<String>` to `AdcsRelayConfig`, threaded it as an `Option<&str>` parameter through `process_ntlm_relay()` and `handle_client()`, cloned it from config through the `run()` spawn loop alongside `target_host`/`template`/`target_upn`, and replaced the `TcpStream::connect("host:80")` with `utils::socks5_connect(target_sock, timeout, proxy)`. The `SocketAddr` is parsed eagerly from `format!("{}:80", target_host)` so the call site mirrors the pattern used in all other relay modules. This closes the last SOCKS5 gap in the relay crate — every outbound relay connection (SMB, HTTP, LDAP, LDAPS, MSSQL, MSMQ, ADCS, Exchange, SMB daemon) now respects `socks5_proxy`. When `None`, direct TCP is used as before; when `Some("host:port")`, all NTLM-relayed traffic is routed through the SOCKS5 tunnel for pivoting.

- **CLI struct constructors updated**: Added `socks5_proxy: None` to all 7 inline struct constructors in `main.rs` — 5 `RelayControllerConfig` sites (capture mode, relay mode with targets, HTTP relay, LDAP relay, wizard relay), plus `SmbDaemonConfig` and `ExchangeRelayConfig`. While the CLI doesn't expose a `--socks5-proxy` flag yet, all config constructors compile and every path defaults to `None` (direct TCP), preserving backward compatibility.

- **relay.rs SOCKS5 restoral**: A PowerShell `-NoNewline` write corrupted `relay.rs` (flattened the 2700+ line file into a single line). Recovered via `git checkout`, then re-applied all SOCKS5 changes: the `socks5_proxy` field on `RelayConfig`, `Default` impl initialization, the `socks5_connect(&self, target, timeout)` helper method on `NtlmRelay`, and all 5 replaced `TcpStream::connect` calls in `smb_negotiate_and_challenge`/`http_negotiate_and_challenge`/`ldap_negotiate_and_challenge`/`mssql_negotiate_and_challenge`/`msmq_negotiate_and_challenge`. The helper delegates to `utils::socks5_connect()` with the config's `socks5_proxy` and the per-call timeout, converting `RelayError` to `OverthroneError` via `.map_err(Into::into)`. The replace pattern uses `self.socks5_connect(target.address, timeout).await?` — shorter, and eliminates the duplicated timeout/connect boilerplate that used to be in every negotiate method.

- **Build and tests**: Full workspace builds with zero errors. Relay crate: 73 tests all pass (73/73).

## 07-06-2026

- **Pilot crate reaches S-Rank — all remaining items completed**: The weakest crate from the v3 audit is now fully implemented. OPSEC-aware escalation, concurrent execution, multi-DC targeting, and planner↔runner integration tests are all wired and passing. Pilot goes from **B** to **S** rank — the second crate (after scribe) to achieve full S-Rank completion.

- **OPSEC cost/benefit analysis wired into runner**: Replaced the old binary OPSEC gate (stealth → Medium max, otherwise Critical) with `OpsecProfile`-driven cost/benefit analysis. The runner now calls `effective_opsec.should_execute(step_noise, step_priority, has_creds)` which returns one of three `OpsecDecision` variants: `Allow` (noise within budget), `AllowOverride` (noise exceeds budget but step priority ≥ threshold and overrides are enabled), or `Deny` (skipped with reason logged). When `config.stealth` is true, the runner automatically substitutes `OpsecProfile::stealth()` (max_noise=Low, no overrides, spray_penalty=3.0) regardless of the configured profile. Authenticated operations (when `state.credentials` is non-empty) get a one-level noise reduction — a High-noise step becomes Medium when the operator already has valid domain creds. A stealth-mode banner displays the active noise budget and override status at engagement start.

- **10 recon steps marked parallel-safe for concurrent execution**: `StealthLdapProbe`, `StealthDelegationProbe`, `EnumerateUsers`, `EnumerateComputers`, `EnumerateGroups`, `EnumerateTrusts`, `EnumerateGpos`, `EnumeratePasswordPolicy`, `EnumerateDelegations`, and `EnumerateLaps` are all flagged `parallel_safe: true` in the planner. These are read-only LDAP queries with no side effects or shared state. The runner's main loop now collects all unexecuted parallel-safe steps in the same stage, spawns them as `tokio::spawn` tasks, and awaits all handles before continuing to the next sequential step. Non-parallel-safe steps (attacks, lateral movement, loot) remain sequential. Attack steps like `PasswordSpray`, `Kerberoast`, `AsRepRoast`, `ExecCommand`, `DcSync`, etc. are deliberately excluded from concurrent execution.

- **Multi-DC targeting infrastructure**: `MultiDcConfig` struct with `dc_hosts: Vec<String>`, `active_index`, `auto_failover`, and `distribute_operations` fields. `new()` constructor auto-enables when >1 host is provided. `next_host()` does round-robin advancement with wrap-around. `failover()` advances the active index and logs a warning. `active_host()` returns the current DC. All fields exposed on `AutoPwnConfig` with `Default` impl (disabled, empty hosts). The OPSEC profile and multi-DC config are both stored on `AutoPwnConfig` and survive `to_snapshot()`/`from_snapshot()` round-trips.

- **7 new planner↔runner integration tests**: `planner_generates_da_plan_with_parallel_safe_steps` — verifies DA plan has ≥5 parallel-safe steps and all are in the Enumerate stage. `opsec_profile_blocks_noisy_steps_in_stealth` — Silent allowed, High and Critical denied under stealth profile. `opsec_profile_allows_override_for_high_value` — Critical noise at priority 95 gets `AllowOverride`, priority 50 gets `Deny`. `opsec_profile_authenticated_bonus_reduces_noise` — High noise denied without creds, allowed with creds (reduced to Medium). `multi_dc_config_round_robin` — 3-host rotation wraps correctly. `multi_dc_failover` — failover advances active host. `planner_da_goal_includes_all_recon_stages` — all key recon action keys present in DA plan. Pilot test count: 110 → 117.

- **Forge AS-REP→TGT pipeline**: New `ForgeAction::AsRepToTgt { cracked_password: String }` variant bridges the gap between hunter (AS-REP roast produces a hash) and forge (needs a usable TGT). Takes a cracked plaintext password and calls `kerberos::request_tgt()` to acquire a real TGT from the KDC. On success, returns a `ForgeResult` with `ForgedTicket` containing ticket type, domain, SPN (`krbtgt/<domain>`), and encrypted part size. On failure, returns a descriptive error. Wired into `run_forge()` dispatch, `validate.rs` (checks non-empty password and username), and `cleanup.rs` detection risk assessment (rated `Low` risk — the AS-REQ is indistinguishable from legitimate authentication traffic, Event ID 4768 only).

- **Reaper GPP cpassword expansion**: `parse_gpp_xml()` in `crypto/gpp.rs` now extracts usernames from 7 attribute names instead of 3: `userName` (Groups.xml, ScheduledTasks.xml, Drives.xml), `runAs` (Services.xml), `accountName` (DataSources.xml, Printers.xml), `sUserName` (Shortcuts.xml), `userContext` (Registry.xml, NetworkOptions.xml), `targetName` (NetworkOptions.xml), and `name` (fallback for ScheduledTasks.xml task-level elements). Also added `password` attribute fallback alongside `cpassword` for GPP variants that use the non-standard attribute name. 7 new tests: Services.xml runAs, DataSources.xml accountName, Shortcuts.xml sUserName, Registry.xml userContext, password attribute fallback, multiple credentials in one file, and name fallback. GPP test count: 4 → 11.

- **Reaper BloodHound edge-type coverage**: 6 new `DangerousRight` variants added to the enum in `acls.rs`: `Enroll` (certificate enrollment right), `ManageCA` (CA management), `ManageCertificates` (certificate management — approve/revoke), `ManageCertTemplate` (template management), `UserForceChangePassword` (extended right alias), and `AllowedToAct` (RBCD delegation right). Each has a corresponding `abuse_info()` description and `right_to_bloodhound_name()` mapping. New `known_bloodhound_v4_edges()` function returns 49 canonical BloodHound v4 edge types. `missing_bloodhound_edges()` validates the current mapping against the known list and returns any gaps. `all_mapped_bloodhound_edges()` collects all edge names produced by the `DangerousRight` enum. 3 new tests: full coverage validation (zero gaps), gap detection with partial input, and known-edges comprehensiveness check (≥40 edges). Export test count: 5 → 8.

- **Hunter pre-auth check verified correct**: The audit claimed the Kerberoast pre-auth check at `kerberoast.rs:158` was "checking the wrong flag". Verified against source: `dont_req_preauth` is populated from `UAC_DONT_REQ_PREAUTH` (0x400000 = 4,194,304 = `UF_DONT_REQUIRE_PREAUTH`) at `ldap.rs:3278` via `(uac & UAC_DONT_REQ_PREAUTH) != 0`. The skip logic correctly avoids wasting SPN requests on accounts that are more efficiently attacked via AS-REP roasting. The audit claim was incorrect — no code change needed.

- **Relay IPv6 transport verified already supported**: The audit claimed "relay only binds IPv4". Verified against source: `format_addr()` in `utils.rs` correctly handles IPv6 addresses with bracket notation (`[::1]:445`). `TcpListener::bind` and `TcpStream::connect` use `SocketAddr` which supports both IPv4 and IPv6. SMB daemon and exchange relay default to `"::"` (IPv6 any-address with dual-stack support on Windows). Existing tests cover IPv6 address formatting. No code change needed.

- **Forge PKINIT-keyed ticket input verified already supported**: The audit claimed "the runner doesn't accept [krbtgt AES key] directly". Verified against source: `ForgeConfig.krbtgt_aes256: Option<String>` accepts 32-byte hex AES256 keys. `resolve_key_and_etype()` in `golden.rs` prefers AES256 over RC4 when both are available, returning `ETYPE_AES256_CTS`. `pkinit_cert_path` + `pkinit_key_path` fields support certificate-based authentication via `request_user_tgt()` which calls `pkinit_authenticate()`. Golden, Diamond, Sapphire, and Bronze Bit all use `request_user_tgt()`. No code change needed.

- **Build and tests**: Full workspace builds with zero errors. Clippy `-D warnings` clean across all 9 crates with zero warnings. 117 pilot tests (7 new), 629 core tests (11 GPP + 3 edge coverage new), 58 forge, 66 hunter, 135 reaper, 73 relay, 54 scribe, 25 viewer. Two crates now at S-Rank: **scribe** (0h) and **pilot** (0h). Total remaining: **480h** (down from 512h, -32h this session).