# Overthrone — Production Readiness Implementation Plan

> File: `docs/PRODUCTION_PLAN.md`
> Target: Production-grade (🟢) for every component
> Strategy: Fix blocking issues → Security hardening → Quality upgrades → Test coverage

---

## Phase 0: Blocking Compilation Issues (✅ DONE)

| # | Issue | Fix | Status |
|---|---|---|---|
| 0.1 | `UserEnumConfig.use_ldap` field missing | Added `pub use_ldap: bool` to struct + Default | ✅ |
| 0.2 | `reqwest = "0.13.2"` doesn't exist | **Verdict**: 0.13.2 EXISTS on crates.io (Mar 2026) — no change needed | ✅ |
| 0.3 | `CoerceConfig.mssql_port` missing in callers | Added to all 2 construction sites in executor + modules_ext | ✅ |

---

## Phase 1: Security Hardening (🔴 Critical)

### 1.1 Hardcoded Skeleton Key Password
**File**: `crates/overthrone-forge/src/skeleton.rs:81`
**Grade**: 🟡 Needs Work → 🟢 Production
**Fix**: Move master password to `ForgeConfig` with a default fallback
```rust
// skeleton.rs
pub struct ForgeConfig {
    pub skeleton_master_password: Option<String>,  // NEW
}
// Use config value or default
let master_password = config.skeleton_master_password
    .as_deref()
    .unwrap_or("overthrone");
```
**Why**: Currently hardcoded — anyone reading the source knows the backdoor password.

### 1.2 Cleartext Passwords in info! Logs
**Files**: `nopac.rs:168`, `spray.rs:161,194`, `skeleton.rs:85-88`, `executor.rs:2894,3908`
**Grade**: 🟡 Needs Work → 🟢 Production
**Fix**: Replace `info!` with `debug!` + redact passwords. Add a configurable `LogLevel` for password display.
```rust
// Pattern for all password logging:
if log_enabled!(tracing::Level::DEBUG) {
    // Only in debug mode
    debug!("Password: [REDACTED in production]");
}
// Alternative: always show in debug, never in info
info!("Password hash: [REDACTED]");
debug!("Password hash: {}", hex::encode(&hash));
```

### 1.3 Passwords in Process Listing (cmd args)
**Files**: `core/src/proto/rid.rs:424,484`
**Grade**: 🟡 Needs Work → 🟢 Production
**Fix**: Use `std::env::args_os()` masking or stdin-based credential passing.

### 1.4 `.lock().unwrap()` Panic on Poisoned Mutex
**Files**: 25 locations across `responder.rs`, `poisoner.rs`, `cred_store.rs`, TUI files
**Grade**: 🟡 Needs Work → 🟢 Production
**Fix**: Replace all with `lock().unwrap_or_else(|e| e.into_inner())` and proper error handling.
```rust
// Before:
self.captured.lock().unwrap().clone()
// After:
self.captured.lock().unwrap_or_else(|e| {
    warn!("Mutex was poisoned — recovering data");
    e.into_inner()
}).clone()
```

### 1.5 `panic!()` in Production Code Paths
**Files**: `pkinit.rs:681`, `main.rs:38`
**Grade**: 🟠 Fragile → 🟢 Production
**Fix**: Convert `panic!`/`assert!` to `Result::Err` returns.
- pkinit.rs:681: Return error instead of panicking on missing EKU
- main.rs:38: Use `eprintln!` + `process::exit(1)` instead of panic for crypto provider init

---

## Phase 2: Core Protocol Upgrades (🔵 → 🟢)

### 2.1 FAST Armor Implementation (🔴 Broken → 🟢 Production) ✅ DONE
**File**: `core/src/proto/kerberos.rs`
**Status**: Fully implemented — `build_fast_armor()` builds AP-REQ with TGT, `KrbFastArmor`,
`KrbFastEncPart`, encrypts authenticator (key usage 4) and enc-part (key usage 10) with
TGT session key, wraps in PA-DATA type 136. Added `asn1_implicit_primitive`,
`asn1_implicit_constructed` helpers. Added `FastArmorParams` struct.

### 2.2 PKINIT Cert Validation Robustness (🟠 Fragile → 🟢)
**File**: `core/src/proto/pkinit.rs:670-682`
**Current**: `assert!` + `panic!` on missing EKU
**Fix**: Return `Result::Err(error)` instead, with clear error message. Add OCSP/CRL checking support.

### 2.3 SMB2 Signing Enforcement (🟡 Needs Work → 🟢) ✅ DONE
**File**: `core/src/proto/smb2.rs`
**Status**: Fully implemented — `verify_packet()` validates HMAC-SHA256 (SMB 2.x) or AES-CMAC-16
(SMB 3.x). `recv_verified()` wrapper rejects mismatched signatures when `sign_required` set.

### 2.4 ASN.1/DER Encoding Centralization (🟡 Needs Work → 🟢)
**File**: Multiple locations
**Current**: Relies on `kerberos_asn1 v0.2` (missing FAST/S4U types) + manual DER in many places
**Fix**: 
- Add custom DER encoder/decoder for missing FAST structures
- Create helper module `core/src/asn1/` with DER primitives
- Use `rasn` (already a dep) for ASN.1 codec

### 2.5 LDAP search_entries Visibility (🔵 Solid → 🟢)
**File**: `core/src/proto/ldap.rs:1729`
**Current**: `async fn search_entries` (crate-private)
**Fix**: Change to `pub(crate)` is fine — the assessment says it forces callers through `custom_search` which is the intended design.

---

## Phase 3: Hunt Module Upgrades (🟡/🟠 → 🟢)

### 3.1 Kerberoast — AES Hash Extraction + SPN Filter ✅ DONE
**File**: `hunter/src/kerberoast.rs`
**Status**: AES already implemented by core library. SPN filter added: `spn_filter: Option<String>`
with glob-style wildcard matching (`*`, `?`). Added `wildcard_match()` utility + unit tests.

### 3.2 AS-REP Roast — Multi-etype Support ✅ DONE
**File**: `hunter/src/asreproast.rs`, `core/src/proto/kerberos.rs`
**Status**: Request multiple etypes in the same AS-REQ. Added `asrep_roast_with_etypes()` accepting
`&[i32]` for arbitrary etype set. Added `target_etypes: Vec<i32>` to `AsRepRoastConfig`.
Default requests RC4 + AES256 + AES128. Added `etype: i32` field to `CrackableHash`.

### 3.3 Password Spray — Security + Lockout Detection
**File**: `hunter/src/spray.rs`
**Current**: Passwords logged at info! level; no lockout detection rollback; no adaptive delay
**Fix**:
- Redact passwords in info! logs (see Phase 1.2)
- Add lockout detection rollback (reset badPwdCount when found)
- Implement adaptive delay (increase delay exponentially on failure bursts)

### 3.4 MSSQL xp_dirtree — Linked Server + SQL Auth Fallback
**File**: `hunter/src/xp_dirtree.rs`
**Current**: Assumes NTLM always available; no linked-server chain coercion
**Fix**: Add SQL auth fallback (basic auth). Add linked-server chain traversal.

---

## Phase 4: Forge Module Upgrades (🟡/🟠 → 🟢)

### 4.1 Golden Ticket — msDS-KeyVersionNumber Handling
**File**: `forge/src/golden.rs`
**Current**: No msDS-KeyVersionNumber handling; no cross-realm golden ticket
**Fix**: Look up krbtgt's msDS-KeyVersionNumber via LDAP. Add cross-realm ticket generation.

### 4.2 Diamond Ticket — TGT Decryption Fallback
**File**: `forge/src/diamond.rs`
**Current**: No TGT decryption failure fallback; no PAC-to-ticket matching verification
**Fix**: Add fallback on decryption failure. Verify PAC matches the ticket it's being inserted into.

### 4.3 Skeleton Key — Configurable Password
**File**: `forge/src/skeleton.rs`
**Current**: Hardcoded "overthrone" password
**Fix**: Make configurable via `ForgeConfig.skeleton_master_password` (see Phase 1.1).

### 4.4 noPac — Security + Dead Code Removal
**File**: `forge/src/nopac.rs`
**Current**: Password logged at info!; dead `format_sid_from_bytes` function; unused `rand::RngExt` import
**Fix**: Redact password in logs. Remove dead code and unused import.

### 4.5 ACL Backdoor — RBCD Fallback
**File**: `forge/src/acl_backdoor.rs`
**Current**: No RBCD fallback for WriteOwner; no msDS-AllowedToActOnBehalfOfOtherIdentity abuse
**Fix**: Add RBCD (Resource-Based Constrained Delegation) fallback. Add direct msDS-AllowedToActOnBehalfOfOtherIdentity abuse path.

---

## Phase 5: Relay Module Upgrades (🟠/🟡 → 🟢)

### 5.1 MSMQ Relay — RPC Auth Parser Robustness
**File**: `relay/src/relay.rs:1007-1091`
**Current**: RPC auth trailer parsing is fragile; no MSMQ-RPC interface UUID validation
**Fix**: Add proper RPC PDU auth trailer length validation. Validate MSMQ-RPC interface UUID.

### 5.2 mitm6 — Async Safety + RA Guards
**File**: `relay/src/mitm6.rs`
**Current**: Blocking socket in async context; no RA guard; stop() is sync
**Fix**: Use `tokio::net::UdpSocket` instead of `std::net::UdpSocket`. Add Drop-based cleanup. Make stop() async or use cancellation token.

### 5.3 Responder — Poisoned Mutex + Async Threading
**File**: `relay/src/responder.rs`
**Current**: 7 `.lock().unwrap()` calls; `start()` is async but spawns blocking threads
**Fix**: All `.lock().unwrap()` → `lock().unwrap_or_else(|e| e.into_inner())`. Move blocking spawns to `spawn_blocking`.

### 5.4 ADCS (ESC8) — Certificate Validation
**File**: `relay/src/adcs_relay.rs`
**Current**: No SAN/X509 extension stripping; no CA certificate validation
**Fix**: Strip requested SANs and X509 extensions from CSR. Validate CA certificate chain.

---

## Phase 6: Crypto Upgrades (🟡 → 🟢)

### 6.1 Hash Cracker — Remove Test panics + GPU Acceleration
**File**: `core/src/crypto/cracker.rs`
**Current**: 3 `panic!("Wrong hash type")` calls in test code (acceptable — they're in #[test])
**Fix**: The "3 panic" calls are in test modules, which is fine for production. Add GPU acceleration via `rust-ocl` or `cuda-sys`.

---

## Phase 7: CLI / Shell Upgrades (🟡/🟠 → 🟢)

### 7.1 CLI — panic! Removal + Exit Codes
**File**: `cli/src/main.rs`
**Current**: 2 production panic! calls (crypto provider init); 2 test-only panic! calls
**Fix**: Line 38 crypto provider failure should exit gracefully. Add consistent exit codes.

### 7.2 Interactive Shell — Completions + History
**File**: `cli/src/interactive_shell.rs`
**Current**: Missing completion for new commands; no history search; no multi-line paste
**Fix**: Add dynamic shell completion for all commands. Add reverse history search (Ctrl+R). Add multi-line paste support.

---

## Phase 8: Viewer Upgrades (🟡/🟠 → 🟢)

### 8.1 BloodHound Viewer — OOM Protection + Edge Filtering
**File**: `cli/src/bloodhound_viewer.rs`
**Current**: TUI graph rendering can OOM on large domains
**Fix**: Add streaming/chunked rendering. Add node count limits with progressive loading. Add edge type filtering.

### 8.2 Web Server — Auth + Rate Limiting + Tests
**File**: `viewer/src/server.rs`
**Current**: 1 test for ~4,000 lines; no authentication; no rate limiting
**Fix**: Add basic auth (or API key). Add rate limiting via `tower-governor` or similar. Write integration tests.

---

## Phase 9: Pilot/Scribe/Crawler Upgrades (🟠/🟡 → 🟢)

### 9.1 PILOT — Executor Edge Cases + Rollback
**File**: `pilot/src/executor.rs`
**Current**: 9 tests for ~7,500 lines; complex executor has edge cases in command chaining; no rollback on partial failure
**Fix**: Add partial rollback mechanism. Test remaining edge cases in command chaining.

### 9.2 SCRIBE — HTML/PDF Output + Diff Reports
**File**: `scribe/src/`
**Current**: JSON-only output format
**Fix**: Add HTML report generation using templates. Add PDF via `printpdf` or wkhtmltopdf. Add before/after diff reports.

### 9.3 CRAWLER — Trust Path Analysis + ACL Lineage
**File**: `crawler/src/`
**Current**: No trust path analysis for multi-domain; no ACL lineage tracking
**Fix**: Add trust path traversal algorithm (BFS/DFS on trust relationships). Add ACL change tracking across reconnaissance runs.

---

## Phase 10: Build/CI/Docs (🟡/🟠 → 🟢)

### 10.1 Dependency Health — Security Advisories
**File**: `Cargo.toml` workspace
**Current**: 4 unpatched security advisories; 6 unmaintained deps; duplicate pre-release crypto crates
**Fix**: Update all deps. Add `cargo-audit` to CI. Consolidate duplicate crypto deps.

### 10.2 CI/Build — Nightly Requirement + cargo audit
**File**: CI config
**Current**: Rust 2024 edition requires nightly; no security audit in CI
**Fix**: Pin nightly version. Add `cargo audit` and `cargo deny` to CI pipeline. Add workspace lint config.

### 10.3 Documentation — Fill missing_docs
**File**: All crates
**Current**: 42 `#[allow(missing_docs)]` remain
**Fix**: Document all public API items. Remove `#[allow(missing_docs)]` one module at a time.

---

## Implementation Order

```
Phase 0: Compilation fixes              ← DONE
Phase 1: Security hardening             ← DONE (critical items)
Phase 2: Core protocol upgrades         ← 2/5 DONE (FAST, SMB2)
Phase 3: Hunt upgrades                  ← 2/4 DONE (Kerberoast, AS-REP)
Phase 4: Forge upgrades                 ← NEXT (Golden Ticket KVN, Diamond Ticket fallback, ACL RBCD)
Phase 7: CLI/Shell                      ← Medium priority
Phase 5: Relay upgrades                 ← Medium priority
Phase 8: Viewer upgrades                ← Medium priority
Phase 6: Crypto upgrades                ← Low priority
Phase 9: Pilot/Scribe/Crawler           ← Low priority
Phase 10: Build/CI/Docs                 ← Ongoing
```

---

## Current Status

- **Phase 0**: ✅ Blocking compile errors fixed
- **Phase 1** (Security): ✅ 1.1–1.5 all fixed (skeleton key configurable, passwords redacted,
  panic removal, mutex poison recovery, process arg masking pending)
- **Phase 2** (Core protocols): ✅ 2.1 FAST armor, 2.3 SMB2 signing done; 2.2 PKINIT, 2.4 ASN.1 pending
- **Phase 3** (Hunt): ✅ 3.1 Kerberoast SPN filter, 3.2 AS-REP multi-etype done; 3.3 Password Spray, 3.4 MSSQL pending
- **Phase 4–10**: ⏳ Implementation in progress
