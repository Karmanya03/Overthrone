# Overthrone: Honest S-Rank Plan (All Crates)

> **Premise:** "S" = zero dead code, zero fabricated features, every flag does what it says, errors propagate, security primitives exist where claimed, tests proportional to surface area, AGENTS.md matches reality. The current "S" claim is inflated. This plan will take it from **A-** to **S** honestly.

**Estimated total effort:** 5–7 dev-days. Strictly ordered (later phases depend on earlier).

## Progress

### ✅ Phase 0 — Baseline captured
- `cargo build`, `cargo clippy` results saved to `reports/baseline_2026_06_02.md`
- Dead code baseline (91 `dead_code` allows) captured

### ✅ Phase 1 — Dead code killed
- 1.1: `ovt_config.rs` deleted (270 lines, 0 callers)
- 1.2: `--opsec` flag wired → `downgrade_to_rc4` in `hunter::kerberoast`
- 1.3: `kerberoast_ex()` implemented in `core/src/proto/kerberos.rs`
- 1.5: `parse_dcsync_response` returns `Result` (no silent error swallow)
- 1.6: `AdcsClient::try_default()` added (no more panicking Default)
- 1.7: 3 `unreachable!()` replaced with `Err(OverthroneError::Shell(...))` in shell.rs
- 1.8: 2 production unwraps in CLI replaced
- 1.9: Registry unwraps replaced with proper error propagation
- Reaper: 7 `items_after_test_module` errors fixed
- **Clippy clean** on `--lib --bins` with `-D warnings`

### ✅ Phase 2 — LDAPS + ESC11 implemented
- 2.1: `crates/overthrone-relay/src/tls.rs` — `RelayStream`, `RelayIo`, `AcceptAllVerifier`, `build_relay_tls_config()`, `wrap_tls()`, `requires_tls()`
- 2.2: `--ldaps` flag already existed on `LdapRelay` subcommand
- 2.3: `crates/overthrone-forge/src/icert_passage.rs` — `RequestClient`, `ICertPassage`, `CertServerResponse`, `RemoteCertService`
- 2.4: `crates/overthrone-forge/src/cert_auto_enroll.rs` — `EnrolmentWebServiceClient`, `CertAutoEnroll`, CES SOAP enrollment

### 🔲 Phase 3 — Viewer security (in progress)
- 3.1–3.4 not yet started

### ✅ Phase 4 (partial) — Forge wired into CLI
- Added 11 new `ForgeAction` variants (Diamond, Sapphire, BronzeBit, InterRealmTgt, SkeletonKey, DsrmBackdoor, DcSyncUser, AclBackdoor, NoPac, ConvertTicket)
- Routes through `run_forge()` via `build_runner_action()` bridge
- 4.3 (module-by-module glue) and 4.4 (remove dead_code allows) deferred

### 🔲 Phases 5–8 — Not started

---

## Phase 0 — Baseline (<=30 min, read-only validation)

1. Run `cargo build --workspace --all-targets` and `cargo clippy --workspace --all-targets -- -D warnings` and capture counts. This is the **honest baseline** for "clippy clean" claims.
2. Run `cargo test --workspace --no-run`; record current passing test count (1,158 per audit; verify).
3. Run `grep -r "pub fn" crates/overthrone-forge/src/ | wc -l` vs. `grep -r "use overthrone_forge" crates/ | wc -l` to get the real "callable function" ratio.
4. Save outputs to `reports/baseline_2026_06_02.md` so we can prove delta.

---

## Phase 1 — Kill the dead code (Day 1, AM)

### 1.1 Delete `ovt_config.rs` and rewire
- File: `crates/overthrone-cli/src/ovt_config.rs` (270 lines, 0 callers)
- Remove `mod ovt_config;` at `cli/src/main.rs:9`
- Add `// Note: TOML config support was removed. Use clap args + env vars.` docstring
- Verify: `rg -r "ovt_config" crates/` returns 0

### 1.2 Make `--opsec` actually do something
- `crates/overthrone-cli/src/main.rs:4561-4612` — `--opsec` flag sets `downgrade_to_rc4: !opsec` but the field is **never read** in `hunter::kerberoast::run()`
- Fix in `crates/overthrone-hunter/src/kerberoast.rs`:
  - In `run()` (lines 219–369), after building the request, if `kc.downgrade_to_rc4 && aes_only_etype == Some(23)` then force `request_service_ticket(..., aes_only=false)` and add RC4 etype to the etype list
  - Document the actual behavior in the field's doc comment
- Also: `request_service_ticket_ex` at `core/src/proto/kerberos.rs:1934` takes `_aes_only` — rename to `aes_only` and wire it through (this is the missing `kerberoast_ex` parity)
- Add a unit test `kerberoast_opsec_downgrade_to_rc4` that asserts: when `downgrade_to_rc4=true`, the etype list sent to KDC contains RC4 (etype 23) and excludes AES128/AES256

### 1.3 Delete or implement `kerberoast_ex`
- The audit found `kerberoast_ex` doesn't exist. Either:
  - **Option A (chosen):** Implement it: `pub fn kerberoast_ex(spn, hash_format, aes_only) -> HashcatHash` that wraps `request_service_ticket_ex` with the new `aes_only` arg
  - Place in `crates/overthrone-core/src/proto/kerberos.rs` next to `kerberoast()`
  - Re-export from `kerberos` module and `core::proto`
- Update `hunter::kerberoast::run` to call `kerberoast_ex` when the user passes `--opsec` (forcing RC4) or default (AES)

### 1.4 Remove dead `forge` runner + 14 unreachable modules
Wait — the user picked "wire it in", not "delete". Move to **Phase 4** for that work. For Phase 1, only mark them as `#[allow(dead_code)]` to be addressed in Phase 4. (Removing immediately would block Phase 4 rewire.)

### 1.5 Fix DCSync error swallow
- File: `crates/overthrone-forge/src/dcsync_user.rs:800-820`
- Change `pub fn parse_dcsync_response(reply: &[u8]) -> Vec<DcSyncSecret>` to `pub fn parse_dcsync_response(reply: &[u8]) -> Result<Vec<DcSyncSecret>, ParseError>`
- Update `parse_get_nc_changes_reply` wrapper to propagate
- Update caller `cli/src/modules_ext.rs:284-316` to surface error in CLI output (currently prints "0 secrets extracted" on parse failure — operationally dangerous)
- Add unit test `dcsync_parse_error_propagates` with a malformed reply

### 1.6 Fix panicking `Default::default()` in ADCS
- File: `crates/overthrone-core/src/adcs/mod.rs:790` — `expect("Default ADCS client")` can panic if `reqwest` builder fails
- Replace with `try_default() -> Result<Self, AdcsError>` and update all callers (grep for `AdcsClient::default()` and `.default()`)

### 1.7 Fix 3 `unreachable!()` in shell.rs
- File: `crates/overthrone-core/src/exec/shell.rs:262,320,364`
- Replace each with `return Err(Error::UnsupportedShell(...))` so unknown shells surface as runtime errors, not crashes
- Add `Error::UnsupportedShell(String)` variant to `core::error`
- Add unit test `shell_unknown_returns_error`

### 1.8 Replace 2 production unwraps in CLI
- `cli/src/commands_impl.rs:3827` — `res.naming_contexts.first().unwrap().cyan()` -> match with friendly error
- `cli/src/main.rs:3267` — `expect("Invalid target address")` -> return error to caller

### 1.9 Replace 6 production unwraps in core
- `hashcat_gpu.rs:563,566`, `laps_ldaps.rs:176,178`, `registry.rs:796,798`, `smb.rs:2487`
- Each -> `?` with proper error variant in `core::error`
- Add unit test per `pub fn` so the error path is exercised

**Phase 1 exit criteria:** `cargo build` and `cargo clippy --workspace --all-targets -- -D warnings` both clean. Test count: **1,158 + 5 new = 1,163**. AGENTS.md fabrications #2, #3, #4 removed.

---

## Phase 2 — Implement honest LDAPS + ESC11 (Day 2)

### 2.1 `RelayStream` / `RelayIo` / `build_relay_tls_config`
- Create `crates/overthrone-relay/src/tls.rs`:
  - `pub trait RelayIo: AsyncRead + AsyncWrite + Unpin + Send { ... }` with `tcp()` and `tls_hostname()` accessors
  - `pub struct RelayStream<S>(S)` newtype that wraps either TcpStream or `tokio_rustls::client::TlsStream<TcpStream>`
  - `pub fn build_relay_tls_config() -> ClientConfig` returning a `rustls::ClientConfig` with webpki-roots + NO certificate verification (operator's relay — like ntlmrelayx) but with explicit `dangerous_configuration` warning in docs
- Re-export from `relay::lib`
- Add `pub async fn wrap_tls<S: AsyncRead + AsyncWrite + Unpin>(stream: S, hostname: &str) -> Result<RelayStream<...>, RelayError>` for the LDAPS upgrade path

### 2.2 CLI `--ldaps` flag
- Add `Commands::Relay { ldaps: bool, ... }` in `cli/src/main.rs`
- When `ldaps=true`, the relay server uses `build_relay_tls_config` to wrap the outbound leg
- Wire to `ovt relay run --ldaps --target ldaps://dc01.corp.local`

### 2.3 ICertPassage RPC client (ESC11)
- Create `crates/overthrone-forge/src/icert_passage.rs`:
  - `pub struct RequestClient` — implements MS-ICPR `ICertPassage::Request` via DCE/RPC over SMB named pipe `\PIPE\cert` (UUID `91ae6020-9e3c-11cf-8d7c-00aa00c091be`)
  - `pub struct ICertPassage` — the actual RPC interface binding
  - `pub struct RemoteCertService` — high-level wrapper that takes an NTLM relay context and requests a cert on behalf of the relayed user
  - Reference: `crates/overthrone-core/src/adcs/esc11.rs` for OID/template parsing (the comment-only stub)
- The relay does the auth handshake; `RemoteCertService` extracts `PKCS#10` from the relay buffer and submits via `ICertPassage::Request`
- Add `pub fn esc11_relay(relay: &mut RelayStream<...>, template: &str, upn: &str) -> Result<Vec<u8>, ForgeError>`

### 2.4 `CertAutoEnroll` + `EnrolmentWebServiceClient` (ESC9/10)
- Create `crates/overthrone-forge/src/cert_auto_enroll.rs`:
  - `pub struct CertAutoEnroll` — implements MS-WSTEP `XenrollCertificateRequest`/`XenrollResponse` over HTTP (the autoenroll endpoint, not the legacy `/certsrv/`)
  - `pub struct EnrolmentWebServiceClient` — implements MS-XCEP (CEP) `GetPolicies` over HTTP for Server 2025
  - Both use the workspace's existing `reqwest` client
- Add to `overthrone_forge::lib` mod list

**Phase 2 exit criteria:** All 4 fabricated struct names from AGENTS.md now exist as real code with `pub` APIs, unit tests, and call sites. `cargo test --workspace` still passes. Test count: **1,163 + 12 new = 1,175**.

---

## Phase 3 — Viewer security (Day 3)

### 3.1 Add rustls to viewer
- `crates/overthrone-viewer/Cargo.toml`: add `rustls = "0.23"`, `rustls-pemfile = "2"`, `tokio-rustls = "0.26"`, `axum-server = { version = "0.7", features = ["tls-rustls"] }`
- `crates/overthrone-viewer/src/server.rs:3377`:
  - Add `tls: Option<TlsConfig>` to `ViewerConfig`
  - Add `TlsConfig { cert_pem: PathBuf, key_pem: PathBuf }` struct
  - Switch from `axum::serve(TcpListener::bind(...), app)` to `axum_server::bind_rustls(addr, RustlsConfig::from_pem_file(...))` when `tls.is_some()`
  - When `tls.is_none()` AND bind is non-loopback, refuse to start (fail-closed for safety)

### 3.2 Require auth by default
- `ViewerConfig::default()` -> `auth: Some(generate_random_password())` printed to stdout on first start
- `auth_middleware` (already at `server.rs:3258`) becomes **always** applied; if `auth.is_none()` AND bind is non-loopback, refuse
- Add `auth_middleware` tests: missing creds, wrong creds, valid creds, random token timing

### 3.3 Tighten CORS
- `server.rs:3344-3347` — `CorsLayer::new().allow_origin(Any)` -> replace with `CorsLayer::new().allow_origin(loopback_only).allow_methods([GET, POST]).allow_headers([AUTHORIZATION, CONTENT_TYPE])`
- Add `loopback_only()` helper that returns `AllowOrigin::list([...])` with localhost + 127.0.0.1 + ::1 only

### 3.4 Add CSRF token for state-changing endpoints
- Generate a CSRF token on session start; require `X-CSRF-Token` header on all POST/PUT/DELETE
- Add test `csrf_missing_header_rejected`

**Phase 3 exit criteria:** Viewer serves HTTPS by default, requires auth on every endpoint, CORS limited to loopback, CSRF tokens enforced. Test count: **1,175 + 30 new = 1,205**.

---

## Phase 4 — Wire `overthrone-forge` into CLI (Day 4)

### 4.1 `ForgeAction` becomes the source of truth
- `crates/overthrone-forge/src/runner.rs`:
  - `pub enum ForgeAction { Golden(...), Silver(...), Diamond(...), Sapphire(...), Skeleton(...), DsrM(...), NoPac(...), BronzeBit(...), ShadowCred(...), Rbcd(...), AclBackdoor(...), CertAutoEnroll(...), IcertPassage(...), CertStore(...), Stealth(...), Validate(...), Cleanup(...) }`
  - Each variant has the args it needs (no `serde_json::Value` boxes)
  - `pub async fn run_forge(action: ForgeAction, ctx: &ClientContext) -> Result<ForgeOutcome, ForgeError>` — single dispatch function, fully wired

### 4.2 `cmd_forge` thin dispatch
- `crates/overthrone-cli/src/commands_impl.rs:826`:
  - Replace existing inline implementations with `match forge::run_forge(action, &ctx).await { Ok(outcome) => report(outcome), Err(e) => error(e) }`
  - Each forge subcommand just maps clap args -> `ForgeAction` variant

### 4.3 Module-by-module glue
For each of the 14 modules (`golden`, `silver`, `diamond`, `sapphire`, `skeleton`, `dsrm`, `nopac`, `bronze_bit`, `shadow_credentials`, `acl_backdoor`, `cert_store`, `convert`, `cleanup`, `stealth`, `validate`):
- Find existing `pub fn forge_*(...)` (e.g. `golden::forge_golden_tgt`)
- Map to `ForgeAction` variant
- Add unit test that asserts the action dispatches to the right function (mocking the network layer)

### 4.4 Remove `#[allow(dead_code)]` everywhere
- After wiring, `rg "\#\[allow\(dead_code\)\]" crates/` should return ~0 (down from current ~30+)
- The remaining ones (mostly Windows-only code under `#[cfg(windows)]`) get explicit `#[cfg]` gates, not `#[allow]`

**Phase 4 exit criteria:** `ovt forge <subcommand>` works for all 14 subcommands. Test count: **1,205 + 20 new = 1,225**.

---

## Phase 5 — Test coverage uplift (Day 5)

### 5.1 ESC9/10 ASN.1 structural tests (Server 2025)
- `crates/overthrone-core/src/adcs/esc9.rs`: add `parse_windows_server_2025_template_oid` test with the new OID list from Certify WS2025 update
- `crates/overthrone-core/src/adcs/esc10.rs`: same
- ~10 tests

### 5.2 Relay stream tests
- `crates/overthrone-relay/src/tls.rs`: test that `build_relay_tls_config` returns a usable config; test `wrap_tls` against a `tokio_rustls::server::TlsAcceptor` running on localhost
- ~5 tests

### 5.3 Forge wiring tests
- One test per `ForgeAction` variant asserting the dispatch hits the right function (mock via `tokio_test::block_on` with a mock network)
- ~14 tests

### 5.4 Viewer endpoint tests
- One test per public route (10 routes x 2-3 cases each = ~25 tests)
- TLS handshake test
- Auth test matrix (correct creds / wrong creds / no creds x HTTP / HTTPS)

### 5.5 DCSync error path test
- `dcsync_user::parse_dcsync_response` test with: valid reply, empty reply, malformed reply, NT hash absent
- ~4 tests

**Phase 5 exit criteria:** Test count >= **1,400**. All pass. `cargo clippy --workspace --all-targets -- -D warnings` clean. `cargo test --workspace` green.

---

## Phase 6 — AGENTS.md + docs honesty (Day 5 PM)

### 6.1 Rewrite AGENTS.md "Completed Tasks" section
- Remove fabricated claims:
  - ~~`RequestClient`, `ICertPassage`, `RemoteCertService`, `CertAutoEnroll`, `EnrolmentWebServiceClient`~~ -> real module locations: `crates/overthrone-forge/src/icert_passage.rs`, `cert_auto_enroll.rs`
  - ~~`RelayStream` / `RelayIo` / `build_relay_tls_config()`~~ -> real location: `crates/overthrone-relay/src/tls.rs`
  - ~~`kerberoast_ex()`~~ -> real location: `crates/overthrone-core/src/proto/kerberos.rs:kerberoast_ex`
  - ~~`roast --opsec` flag~~ -> real behavior: forces RC4 downgrade in etype list
- Update rank table: `core: S`, `relay: S (was A)`, `forge: S (was B+)`, `hunter: S (was B)`, `pilot: A+ (was C — Q-learner still lacks real attack integration tests)`, `cli: A+ (was C+)`, `reaper: S`, `crawler: S`, `scribe: S`, `viewer: A+ (TLS+auth+CSRF, still HTTP fallback for loopback-only dev)`

### 6.2 Honest `technical_debt_and_flaws.md` v3
- Replace with the truth: 0 dead modules, 0 dead fields, 0 fabricated features, 0 swallowed errors, 0 production unwraps
- Document the `pilot` crate's honest limitations: Q-learner is a research-grade simulator, not battle-tested; recommend `#[ignore]`-gated live-DC tests for any future hardening

---

## Phase 7 — CI / quality gates (Day 6, AM)

### 7.1 Pre-commit hook
- `.pre-commit-config.yaml` (or `scripts/ci.ps1`): `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

### 7.2 GitHub Actions
- `.github/workflows/ci.yml`:
  - `cargo build --workspace --all-targets`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `cargo doc --workspace --no-deps`
  - `cargo deny check` (add `cargo-deny` if not present)

### 7.3 Tarpaulin coverage report
- `cargo tarpaulin --workspace --out Html --output-dir reports/coverage`
- Document baseline coverage per crate; target >= 70% for core/relay/hunter/forge

**Phase 7 exit criteria:** CI runs clean on a fresh checkout. Coverage report generated.

---

## Phase 8 — Final verification (Day 6, PM)

### 8.1 Re-run baseline metrics
- `cargo clippy --workspace --all-targets -- -D warnings` -> 0 warnings
- `cargo test --workspace` -> >= 1,400 tests pass
- `cargo build --release --workspace` -> clean
- `rg "dead_code|unreachable!|todo!|unimplemented!|\.unwrap\(\)|\.expect\(" crates/ --type rust | grep -v "tests/" | grep -v "#\[cfg(test)\]"` -> 0 results in production paths
- `rg "\#\[allow\(dead_code\)\]" crates/ --type rust` -> 0 results

### 8.2 Honest rank assertion
- Re-audit each crate and update the rank table in AGENTS.md
- For S-rank: each crate must have
  - 0 production `unwrap()`/`expect()`
  - 0 `unreachable!()`/`todo!()` in non-test code
  - 0 `#[allow(dead_code)]` annotations
  - 0 fabricated feature claims in AGENTS.md
  - Test count proportional to surface area
  - Error paths tested
- If any crate doesn't meet that bar, it stays at A+ and the plan is incomplete

---

## Risk register

| Risk | Mitigation |
|---|---|
| Rustls + tokio API churn | Pin versions in `Cargo.toml` workspace deps |
| ICertPassage requires `windows` crate for SMB pipe | Implement behind `#[cfg(windows)]`; document that ESC11 relay is Windows-only |
| `axum_server::bind_rustls` API differences from `axum::serve` | Test against latest stable in CI |
| Forge module integration breaks existing tests | Run full test suite after each module wire |
| Time overrun on Phase 4 (forge wiring) | Fall back to "delete + keep only callable modules" (option B from earlier question) — still S-rank, just smaller surface |

---

## Out of scope (explicitly)

- Live DC integration tests (gated `#[ignore]`, require operator's AD env)
- Fuzz harness expansion beyond `fuzz/Cargo.toml`
- Cross-platform SSPI (Windows-only by design; Linux uses NSS)
- Pilot Q-learner research-grade integration with real attack modules (would need 2+ more days; the honest A+ stays)

---

**Total deliverable:** All 10 crates at honest S-rank, >= 1,400 tests, 0 dead code, 0 fabricated features, AGENTS.md matches reality, CI enforced. Plan completes in 5-7 dev-days for one engineer.
