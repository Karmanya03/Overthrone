# Fix Plan — All Remaining Gaps

**Target:** Make every crate production-grade by eliminating all stubs, placeholders, and unimplemented paths.

---

## Phase 1 — Low-Hanging Fruit (1-2 files each, well-scoped)

### 1. PowerView SID Placeholder — overthrone-reaper:powerview.rs:189
**Problem:** `let sid = "S-1-5-...".to_string();` instead of parsing binary `objectSid`.  
**Fix:** Add a `sid_bytes_to_string(bytes: &[u8]) -> String` helper that decodes the standard SID binary structure (revision, subAuthorityCount, identifierAuthority, subAuthorities) into `S-R-IA-SA-...` format. Use the raw bytes from `entry.attrs.get("objectSid")`.  
**Files:** `crates/overthrone-reaper/src/powerview.rs`  
**Risk:** Trivial — purely local parsing, no new deps.  
**Effort:** ~30 lines.

### 2. Viewer `layout_ms: 0` — overthrone-viewer:graph_data.rs:275
**Problem:** `layout_ms: 0` hardcoded in `GraphLoadMetrics`.  
**Fix:** Remove `layout_ms` from the struct since layout is done client-side in Three.js. Update the instantiation site and any serialization consumers.  
**Files:** `crates/overthrone-viewer/src/graph_data.rs`  
**Risk:** Trivial — struct field removal requires updating consumers (JSON serialization).  
**Effort:** ~10 lines.

### 3. CLI Doctor Module Wiring — overthrone-cli:commands/doctor.rs 
**Problem:** Module is complete (407 lines) but has `#![allow(dead_code)] // WIP — not yet wired into dispatch`.  
**Fix:**  
- Remove `#![allow(dead_code)]` from doctor.rs  
- Add `Doctor` variant to the CLI command enum  
- Wire `doctor::run()` into the command dispatch  
- Add `--dc` flag for DC connectivity checks  
**Files:** `crates/overthrone-cli/src/commands/doctor.rs`, `crates/overthrone-cli/src/commands/mod.rs`, command-dispatch file  
**Risk:** Low. Module is fully implemented, just needs plumbing.  
**Effort:** ~20 lines.

### 4. Scribe PDF Evidence & Missing Sections — overthrone-scribe:pdf.rs
**Problem:** `render_finding_page()` in PDF is missing: (a) evidence block, (b) per-finding MITRE mappings, (c) references, (d) detailed mitigations.  
**Fix:** Add these sections mirroring the markdown renderer. Un-dead the `write_mono()` method for evidence code blocks.  
**Files:** `crates/overthrone-scribe/src/pdf.rs`  
**Risk:** Low. Pure rendering changes.  
**Effort:** ~50 lines.

---

## Phase 2 — Medium Complexity (Single-file, protocol-level work)

### 5. Relay mDNS Poisoning — overthrone-relay:poisoner.rs
**Problem:** `mdns: true` config flag exists but `run_mdns_listener()` was never implemented.  
**Fix:** Implement mDNS responder:
- Bind UDP socket to `0.0.0.0:5353`, multicast group `224.0.0.251`
- Parse DNS-style query packets (same wire format as LLMNR/DNS)
- Build spoofed A-record response pointing to `poison_ip`
- Hook into `Poisoner::start()`  
**Note:** mDNS uses standard DNS message format (RFC 6762). The existing `LlmnrHeader` parser can be reused.  
**Files:** `crates/overthrone-relay/src/poisoner.rs` (add ~150 lines)  
**Risk:** Low-medium. Well-known protocol, same wire format as DNS/LLMNR.  
**Effort:** ~150 lines.

### 6. Relay LDAP Responder — overthrone-relay:responder.rs
**Problem:** `ldap: true` in config but no LDAP server is spawned.  
**Fix:** Implement minimal LDAP responder:
- Listen on port 389
- Parse LDAP bind requests (BER-encoded, look for NTLM SASL bind OID `1.3.6.1.4.1.311.2.2.10`)
- Extract NTLMSSP Negotiate, respond with Challenge, capture Authenticate
- Same blocking-thread pattern as HTTP/SMB/MSMQ servers  
**Note:** The crate already has full BER LDAP encoding in `relay.rs`.  
**Files:** `crates/overthrone-relay/src/responder.rs` (add ~200 lines)  
**Risk:** Medium. Requires understanding LDAP SASL NTLM bind protocol.  
**Effort:** ~200 lines.

### 7. Relay ADCS CSR Generation — overthrone-relay:adcs_relay.rs
**Problem:** `build_csr()` returns a static base64-encoded skeleton CSR with UPN as a `#` comment.  
**Fix:** Use `overthrone_core::adcs::csr` module (`RsaKeyPair`, `CsrSubject`, `SubjectAltName`, `SanEntry`, `create_client_auth_csr`) to dynamically generate a proper CSR with UPN SAN.  
**Files:** `crates/overthrone-relay/src/adcs_relay.rs` (rewrite `build_csr()`)  
**Risk:** Medium. Requires understanding the CSR API in overthrone-core.  
**Effort:** ~40 lines.

---

## Phase 3 — High Complexity (Multi-file, cross-crate changes)

### 8. PKINIT OCSP/CRL Checking — overthrone-core:proto/pkinit.rs
**Problem:** Both functions log a warning and return `Ok(())`.  
**Fix:**  
- Convert both to `async fn`  
- **OCSP:** Build OCSPRequest DER using `yasna`, HTTP POST via `reqwest`, parse OCSPResponse, check `certificateStatus`  
- **CRL:** HTTP GET via `reqwest`, parse CRL DER using `x509_parser::revocation::CertificateRevocationList`, check serial against revoked list  
- Soft-fail on network errors, hard-fail on confirmed revocation  
**Files:** `crates/overthrone-core/src/proto/pkinit.rs`  
**Risk:** High — OCSP DER encoding is complex.  
**Effort:** ~200 lines.

### 9. C2Executor::execute — overthrone-core:exec/mod.rs
**Problem:** Returns error "use C2Manager.exec_command() instead" (which doesn't exist).  
**Fix (Option A):** Make `C2Executor` hold an `Arc<dyn C2Channel>` directly (replace `PhantomData`), call `channel.execute_command(session_id, command)`.  
**Files:** `crates/overthrone-core/src/exec/mod.rs`, `crates/overthrone-core/src/c2/mod.rs`  
**Risk:** Medium.  
**Effort:** ~50 lines.

### 10. ADCS ESC2-ESC16 Automation — overthrone-pilot:executor.rs
**Largest effort.** Per-variant breakdown:

**Already automatable (exploiters exist in core, just need wiring):**
- **ESC2** — create `exec_adcs_esc2()` mirroring ESC1 pattern  
- **ESC3** — two-step: enrollment agent cert → user cert  
- **ESC13** — policy OID in CSR extension  
- **ESC15** — SAN-enabled CSR submission  

**Need LDAP UPN modification wrapper:**
- **ESC9** — LDAP modify UPN → CSR → restore UPN  
- **ESC10** — variant A (trivial CSR) or variant B (UPN poison like ESC9)  
- **ESC16** — same UPN poison pattern  

**Need more infrastructure (lower priority):**
- **ESC5** — LDAP ACL modification on CA object  
- **ESC7** — DCOM/RPC to CertSrv or certutil shell  
- **ESC8** — already handled by relay crate, just needs integration  
- **ESC11** — RPC relay to ICPR endpoint  
- **ESC12** — SMB + certutil on CA server  
- **ESC14** — LDAP altSecurityIdentities + PKINIT  

**Priority order:** ESC2 → ESC15 → ESC13 → ESC3 → ESC9 → ESC16 → ESC10 → ESC5 → ESC8/11/12/14/7  

**Files:** `crates/overthrone-pilot/src/executor.rs` (primary), exploiters already exist in `crates/overthrone-core/src/adcs/`  
**Risk:** Medium-High.  
**Effort:** ~300-600 lines total.

---

## Phase 4 — Cleanup

### 11. Remove FTP Responder Config — overthrone-relay:responder.rs
**Problem:** `ftp: true` flag exists, server never spawned. FTP NTLM relay is obsolete.  
**Fix:** Remove the config flag and associated log line.  
**Effort:** ~5 lines.

### 12. CLI Dead Code Audit — overthrone-cli
**Problem:** 27 `#[allow(dead_code)]` annotations.  
**Fix:** Audit each — remove if truly unused, add doc comments for future intent.  
**Effort:** Audit of ~27 sites.

### 13. Relay mitm6 Integration — overthrone-relay:lib.rs
**Problem:** `Mitm6` module is fully implemented but not wired into `RelayController`.  
**Fix:** Add `Mitm6` field, wire `start()`/`stop()`.  
**Effort:** ~20 lines.

---

## Summary

| # | Item | Crate | Difficulty | Lines | Phase |
|---|------|-------|-----------|-------|-------|
| 1 | PowerView SID parsing | reaper | Trivial | 30 | 1 |
| 2 | layout_ms cleanup | viewer | Trivial | 10 | 1 |
| 3 | Wire doctor module | cli | Low | 20 | 1 |
| 4 | PDF evidence sections | scribe | Low | 50 | 1 |
| 5 | mDNS poisoner | relay | Low | 150 | 2 |
| 6 | LDAP responder | relay | Medium | 200 | 2 |
| 7 | ADCS CSR generation | relay | Medium | 40 | 2 |
| 8 | PKINIT OCSP/CRL | core | High | 200 | 3 |
| 9 | C2Executor fix | core | Medium | 50 | 3 |
| 10 | ADCS ESC2-16 wiring | pilot | Med-High | 300-600 | 3 |
| 11 | Remove FTP config | relay | Trivial | 5 | 4 |
| 12 | Dead code audit | cli | Low | audit | 4 |
| 13 | mitm6 integration | relay | Low | 20 | 4 |

**Estimated total: ~1,100-1,400 lines of new/changed code.**

---

## Key Questions for You

1. **FTP responder:** Remove flag or implement? My recommendation: remove it — FTP NTLM relay is effectively obsolete in modern AD.
2. **ADCS ESC priority:** Do all ESC variants or just the ones with existing exploiters (ESC2, ESC3, ESC9, ESC10, ESC13, ESC15, ESC16)?
3. **PKINIT OCSP soft-fail:** Should OCSP/CRL failures hard-fail (reject cert) or soft-fail (log + accept)? Real browsers soft-fail.
4. **C2Executor approach:** Option A (hold `Arc<dyn C2Channel>` directly) or Option B (add `exec_command` to `C2Manager`)?
