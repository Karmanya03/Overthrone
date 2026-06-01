# 💀 BRUTALLY HONEST AUDIT: Overthrone Flaws & Limitations — June 2026

> **Status Key:** ✅ Fixed | 🟡 Partially / Overstated in previous doc | ❌ Still Broken
>
> Previous version (May 2026) contained **several fabricated claims** — things marked as "Already Implemented" or "FIXED" that don't exist in code. This version corrects every inaccuracy.

---

## CRITICAL: What the previous doc lied about

| Previous claim | Reality | Status |
|---------------|---------|--------|
| eferral_state_machine() exists | Inline cross-realm code exists in equest_service_ticket() but **no named function** exists | 🟡 Overstated |
| drsuapi.rs in proto/ with DsGetNCChanges | DCSync code in orge/dcsync_user.rs and pilot/executor.rs, **not** in proto | 🟡 Overstated |
| strip_mic_from_type3 used at elay.rs:668 | Used at smb_daemon.rs:1103 but **NOT** at elay.rs:668 | ❌ Wrong |
| 6 coercion trigger types exist | Functions exist (`trigger_printer_bug`, `trigger_petitpotam`, `trigger_dfs_coerce` in core `proto/coerce.rs`) but **misnamed** in AGENTS.md (functions, not `Trigger*` structs) | 🟡 Overstated |
| RequestClient, ICertPassage, RemoteCertService exist | ICertPassage only in a doc comment; others don't exist | ❌ Fabricated |
| kerberoast_ex() with es_only param exists | Only kerberoast() exists. kerberoast_ex() never existed | ❌ Fabricated |
| CLI -U flag worked | Was broken until this session's fix | ❌ Was broken |
| IPv6 fragment test passed | Was broken (index off-by-2) until this session | ❌ Was broken |

---

## 1. overthrone-core — **Honest Rank: S** (previous: S)
### ✅ Confirmed
- SMB3 Encryption: 4 functions exist in smb2.rs:1849-1920 (AES-128-GCM Transform_Header)
- Kerberos cross-realm: inline handling in equest_service_ticket() at kerberos.rs:1261
- PEAS module: 10 submodules wired in (this session)
- hashcat_gpu: #[cfg(not(feature = "opsec"))] gated (this session)

### ❌ Not addressed
1. strip_mic_from_type3 (
tlm.rs:530-598) — **ZERO unit tests**. Critical relay function, completely untested.
2. 6 .unwrap() in production paths: hashcat_gpu.rs:563,566, laps_ldaps.rs:176,178, egistry.rs:796,798, smb.rs:2487 — all will panic on failure
3. unreachable!() in shell.rs:262,320,364 — crashes on unrecognized OS

---

## 2. overthrone-relay — **Honest Rank: A** (previous: S, inflated)
### ✅ Confirmed
- MIC stripping works: clears SIGN/SEAL/ALWAYS_SIGN, walks AV_PAIRs, zeros MIC
- Signature stripping: 3 layers in smb_daemon.rs, all unit-tested
- Relay scenarios: SMB→SMB, SMB→LDAP, HTTP→Exchange, TDS/MSSQL

### ❌ Not addressed
1. strip_mic_from_type3 NOT used at elay.rs:668 as claimed — only in smb_daemon.rs
2. No HTTP→SMB relay path (asymmetric)
3. Unicode box-drawing chars (═, ║, ╔) make elay.rs binary-detectable in PowerShell
4. 17 unused deps removed this session (was cargo-culted)

---

## 3. overthrone-forge — **Honest Rank: B+** (previous: A, inflated)
### ✅ Confirmed
- Silver/Golden/Diamond: real PAC, proper ASN.1, correct checksums
- DCSync: full DRSUAPI with DRSBind, DRSGetNCChanges, EXOP_REPL_OBJ

### ❌ Not addressed
1. **DCSync silently swallows errors** (dcsync_user.rs:800-819) — returns empty Vec on parse failure instead of error. "0 credentials" reported instead of failure.
2. **Cert abuse HTTP code DOES NOT EXIST** — RequestClient, ICertPassage, RemoteCertService are fabrications. Previous doc lied.
3. Raw DCOM ICertRequestD not implemented (this was honestly marked)

---

## 4. overthrone-hunter — **Honest Rank: B** (previous: B+, inflated)
### ✅ Confirmed
- AS-REP roasting: works (LDAP enum + hashcat-18200 output)
- Kerberoast: works (RC4/AES128/AES256, hashcat-13100)
- LDAP pagination via ldap3 backend

### ❌ Not addressed
1. **downgrade_to_rc4 field is DEAD CODE** (kerberoast.rs:48) — field exists, NEVER read in un(). kerberoast_ex() never existed. Setting the field has zero effect.
2. IPv6 RCE module has 3 #[allow(dead_code)] — incomplete exploit path
3. No ASN.1 PagedResults for raw NTLM/LDAP (honestly acknowledged)

---

## 5. overthrone-pilot — **Honest Rank: C** (previous: S, GROSSLY inflated)
### ⚠️ Re-audit correction (this session)
Coercion code IS real — `trigger_printer_bug`, `trigger_petitpotam`, `trigger_dfs_coerce` exist as implementations in `core/src/proto/coerce.rs`. The AGENTS.md had type names (`TriggerNetworkProvider`, etc.) that don't match actual function names, but the functionality was not fabricated. `coerce_tcp.rs` now wired into `lib.rs` (this session).

### ❌ Remaining issues
1. Q-learner has no integration tests with real attack modules
2. AdaptiveEngine had `#[allow(dead_code)]` on `max_retries` (fixed this session — now used as global fallback)
3. Depends on real coercion functions in core crate

---

## 6. overthrone-cli — **Honest Rank: C+** (previous: B+)
### ✅ Fixed this session
- -U flag conflict resolved
- --json-log actually wired in
- 	ui-widget-list unused dep removed

### ❌ Not addressed
1. **ovt_config.rs = 130 lines DEAD CODE** — entire TOML config subsystem (load(), rom_file(), pply_cli_override(), save(), dirs_home()) never called. Clap args are used exclusively.
2. session_store.rs has 5 dead methods (#[allow(dead_code)])
3. oast --opsec flag is COSMETIC — sets downgrade_to_rc4 which is never read
4. unreachable!() at 3 match arms (main.rs:3850,3977,4905)
5. c2_cmd.rs and plugin_cmd.rs orphaned

---

## 7. overthrone-reaper — **Honest Rank: A** (previous: B+, undervalued)
### ✅ Solid
- 168 tests — highest after core
- 33 ADCS ESC integration tests with real SDDL parsing
- Good edge-case coverage (LAPS, GPP, SNAFFLER, trusts)

### ❌ Not addressed
1. items_after_test_module in 7 submodule files (style only)
2. 6 live-DC tests are #[ignore] — no CI validation against real AD

---

## 8. overthrone-crawler — **Honest Rank: A** (previous: B+, undervalued)
### ✅ Confirmed
- PacingConfig/OpsecPacer with stealth/fast presets, semaphore concurrency, unit tests
- 91 tests, good coverage

### ❌ Not addressed
1. opsec.rs deleted this session (was 151 lines dead code)
2. TCP source-port rotation not implemented (platform syscall work)

---

## 9. overthrone-scribe — **Honest Rank: A** (previous: S, inflated)
### ✅ Confirmed
- --json-log wired, ReportFormat::Json works
- PDF generation via printpdf (valid %PDF- output)
- Report content: CVSS, MITRE mapping, remediation, redacted evidence

### ❌ Not addressed
1. pipeline.rs was orphaned (wired in this session)
2. items_after_test_module in mapper.rs:243 and mitigations.rs:299
3. EngagementSession::new() has no findings population path

---

## 10. overthrone-viewer — **Honest Rank: B** (previous: S, grossly inflated)
### ✅ Confirmed
- Terminal injection sanitization: sanitize_ad_string() and sanitize_btreemap() work

### ❌ Not addressed
1. **No HTTPS** — plain HTTP, credentials in cleartext
2. **No CORS, no CSRF** — XSS machine if deployed externally
3. **Auth is optional** — basic auth exists but isn't enforced
4. **9 tests only** — lowest of any crate
5. **10 screenshot tests all #[ignore]** — requires Playwright

---

## Final Verdict Matrix (BRUTALLY HONEST, June 2026)

| Crate | Honest Rank | Previous | Delta | Key Blockers |
|-------|-------------|----------|-------|-------------|
| core | **S** | S | = | 6 unwrap() in prod, unreachable!() in shell, MIC strip 0 tests |
| relay | **A** | S | ↓1 | MIC strip not at relay.rs:668, no HTTP→SMB, box-draw chars |
| forge | **B+** | A | ↓1 | DCSync swallows errors, cert abuse HTTP code FAKE |
| hunter | **B** | B+ | ↓1 | downgrade_to_rc4 dead field, kerberoast_ex() never existed |
| pilot | **C** | S | ↓3 | Coercion code real (misnamed in docs), coerce_tcp.rs wired (this session), Q-learner no integration tests |
| cli | **C+** | B+ | ↓1 | 130-line dead config, roast --opsec does nothing, 2 orphaned cmd files |
| reaper | **A** | B+ | ↑1 | Actually solid — undervalued |
| crawler | **A** | B+ | ↑1 | Actually solid — undervalued |
| scribe | **A** | S | ↓1 | pipeline was orphaned (fixed), test modules misplaced |
| viewer | **B** | S | ↓2 | No HTTPS/CORS/CSRF, 9 tests, screenshot tests ignored |

## Summary of fabricated claims
The previous doc contained **7 inaccurate claims** about "FIXED" or "Already Implemented" features. Correction: coercion triggers are real code (misnamed in AGENTS.md, not fabricated). Worst remaining fabrication: cert abuse HTTP module (claimed real, doesn't exist).

## Actionable next steps
### 🔴 Must fix
1. Pilot coercion triggers: names are functions not `Trigger*` structs. Wired into pilot. Remaining: Q-learner integration tests.
2. DCSync error swallowing: propagate error instead of empty Vec
3. Remove downgrade_to_rc4 dead field + roast --opsec cosmetic flag
4. Delete or implement ovt_config.rs dead config system (130 lines)

### 🟡 Should fix
5. Add unit tests for strip_mic_from_type3
6. Replace 6 .unwrap() with proper error handling
7. Replace unreachable!() with runtime errors in shell.rs
8. Add HTTPS + CORS to viewer

### 🟢 Nice to have
9. Fix items_after_test_module in 9 files
10. Fix box-drawing chars in relay.rs
11. Wire in or delete orphaned c2_cmd.rs, plugin_cmd.rs, coerce_tcp.rs
