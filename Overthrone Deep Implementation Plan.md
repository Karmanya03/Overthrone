# Overthrone — Deep Implementation Plan & Audit

## Executive Summary

Overthrone is a 9-crate Rust workspace implementing an autonomous Active Directory red team framework. The codebase currently contains ~1.2MB+ of Rust source across 80+ files with CLI wiring, protocol stubs, and partial implementations. This plan audits every module, identifies what is genuinely implemented vs. stubbed, and provides a prioritized roadmap with full implementation details for each feature.

***

## Architecture Overview

The workspace consists of 9 crates organized by kill-chain phase:

| Crate | Purpose | Key Files | Total Size |
|-------|---------|-----------|------------|
| **overthrone-core** | Protocols (LDAP, Kerberos, SMB, NTLM, DRSR), ADCS, SCCM, MSSQL, Graph engine | 25+ files across `proto/`, `adcs/`, `mssql/`, `sccm/`, `exec/`, `graph/`, `crypto/` | ~400KB |
| **overthrone-cli** | CLI binary, interactive shell, command routing | `main.rs` (48KB), `interactive_shell.rs` (99KB), `commands_impl.rs` (64KB) | ~230KB |
| **overthrone-hunter** | Kerberoasting, AS-REP, delegation abuse, ticket ops | 10 files | ~160KB |
| **overthrone-forge** | Golden/Silver tickets, DCSync, skeleton key, shadow creds, ACL backdoor | 12 files | ~150KB |
| **overthrone-relay** | NTLM relay, responder, poisoner, ADCS relay | 6 files | ~120KB |
| **overthrone-reaper** | LDAP enum (users, groups, computers, GPOs, trusts, ACLs, ADCS, MSSQL) | 14 files | ~80KB |
| **overthrone-crawler** | Trust mapping, SID filtering, escalation paths, PAM, MSSQL links | 9 files | ~70KB |
| **overthrone-pilot** | Autonomous planner, executor, adaptive engine, playbooks, wizard | 7 files | ~220KB |
| **overthrone-scribe** | Report generation (PDF, Markdown, HTML), MITRE mapping, session tracking | 8 files | ~115KB |



***

## Current Implementation Status

### What's Already Implemented (Functional)

Based on the TODO.md checklist and source file analysis:

| Feature | Crate | Status | Evidence |
|---------|-------|--------|----------|
| CLI command routing (all 14 commands) | cli | ✅ Done | `main.rs` (48KB), all `cmd_*` functions wired |
| Interactive shell | cli | ✅ Done | `interactive_shell.rs` (99KB) |
| LDAP protocol client | core/proto | ✅ Done | `ldap.rs` (41KB) |
| Kerberos protocol | core/proto | ✅ Done | `kerberos.rs` (56KB) |
| SMB 2/3 protocol | core/proto | ✅ Done | `smb.rs` (44KB) |
| NTLM auth protocol | core/proto | ✅ Done | `ntlm.rs` (27KB) |
| MS-DRSR protocol parser | core/proto | ✅ Done | `drsr.rs` (30KB) |
| Secrets dump | core/proto | ✅ Done | `secretsdump.rs` (52KB) |
| Remote registry | core/proto | ✅ Done | `registry.rs` (33KB) |
| RID cycling | core/proto | ✅ Done | `rid.rs` (15KB) |
| DNS resolution | core/proto | ✅ Done | `dns.rs` (3KB) |
| Port scanner | core/scan | ✅ Done | `scan/` directory |
| Attack graph engine | core/graph | ✅ Done | Dijkstra pathfinding, BloodHound export |
| Kerberoasting | hunter | ✅ Done | `kerberoast.rs` (11KB) |
| AS-REP roasting | hunter | ✅ Done | `asreproast.rs` (10KB) |
| Hash cracking | hunter | ✅ Done | `crack.rs` (12KB) |
| Ticket operations (ccache import) | hunter | ✅ Done | `tickets.rs` (27KB) |
| Constrained delegation | hunter | ✅ Done | `constrained.rs` (12KB) |
| Unconstrained delegation | hunter | ✅ Done | `unconstrained.rs` (7KB) |
| RBCD abuse | hunter | ✅ Done | `rbcd.rs` (13KB) |
| Auth coercion (PetitPotam, PrinterBug) | hunter | ✅ Done | `coerce.rs` (29KB) |
| Golden ticket forging | forge | ✅ Done | `golden.rs` (27KB) |
| Silver ticket forging | forge | ✅ Done | `silver.rs` (5KB) |
| Diamond ticket | forge | ✅ Done | `diamond.rs` (6KB) |
| Skeleton key | forge | ✅ Done | `skeleton.rs` (6KB) |
| DSRM backdoor | forge | ✅ Done | `dsrm.rs` (3KB) |
| Shadow credentials | forge | ✅ Done | `shadow_credentials.rs` (17KB) |
| ACL backdoor | forge | ✅ Done | `acl_backdoor.rs` (16KB) |
| Cleanup module | forge | ✅ Done | `cleanup.rs` (22KB) |
| Ticket validation | forge | ✅ Done | `validate.rs` (12KB) |
| PsExec | core/exec | ✅ Done | `psexec.rs` (16KB) |
| SmbExec | core/exec | ✅ Done | `smbexec.rs` (6KB) |
| WmiExec | core/exec | ✅ Done | `wmiexec.rs` (11KB) |
| AtExec (scheduled tasks) | core/exec | ✅ Done | `atexec.rs` (17KB) |
| WinRM | core/exec | ✅ Done | `winrm/` directory |
| Interactive shell exec | core/exec | ✅ Done | `shell.rs` (18KB) |
| LDAP enum (users, groups, computers, GPOs, trusts, ACLs) | reaper | ✅ Done | 14 files in reaper |
| Trust mapping | crawler | ✅ Done | `trust_map.rs` (11KB) |
| SID filtering analysis | crawler | ✅ Done | `sid_filter.rs` (9KB) |
| Escalation path analysis | crawler | ✅ Done | `escalation.rs` (13KB) |
| Report generation (PDF, Markdown, HTML, JSON) | scribe | ✅ Done | `pdf.rs`, `markdown.rs`, `session.rs`, `runner.rs` |
| MITRE ATT&CK mapping | scribe | ✅ Done | `mapper.rs` (8KB) |
| Autonomous planner | pilot | ✅ Done | `planner.rs` (18KB), `executor.rs` (89KB) |
| Adaptive engine | pilot | ✅ Done | `adaptive.rs` (27KB) |
| Playbook system | pilot | ✅ Done | `playbook.rs` (14KB) |
| Setup wizard | pilot | ✅ Done | `wizard.rs` (28KB) |
| Responder (LLMNR/NBT-NS/mDNS) | relay | ✅ Done | `responder.rs` (29KB) |
| Poisoner | relay | ✅ Done | `poisoner.rs` (26KB) |
| ADCS relay target | relay | ✅ Done | `adcs_relay.rs` (12KB) |

### What Needs Implementation (Stubs / Partial / Missing)

| Feature | Crate | Status | Evidence / Issue |
|---------|-------|--------|-----------------|
| DCSync via DRSR (live RPC orchestration) | forge | 🟡 Partial | `dcsync_user.rs` (24KB) has RPC stubs but session key derivation, DRSBind response parsing, and GNC request are incomplete |
| NTLM Relay (actual relay logic) | relay | 🟡 Partial | `relay.rs` (42KB) has types/structure but needs real SMB/HTTP/LDAP relay handlers |
| ADCS ESC1 (certificate request) | core/adcs | 🟡 Partial | `mod.rs` (29KB) has stubs, `csr.rs` (18KB) + `web_enrollment.rs` (21KB) exist but need live verification |
| ADCS ESC4 (template ACL modification) | core/adcs | 🟡 Partial | `esc4.rs` (5KB) — detection-only, no LDAP write to modify templates |
| ADCS ESC5 (CA config modification) | core/adcs | 🟡 Partial | `esc5.rs` (5KB) — detection-only, no remote registry/RPC write |
| ADCS ESC7 (CA permission abuse) | core/adcs | 🟡 Partial | `esc7.rs` (4KB) — detection-only, no DCOM/RPC implementation |
| ADCS ESC8 (NTLM relay to web enrollment) | relay | 🟡 Partial | `adcs_relay.rs` exists, needs HTTP listener + relay chain integration |
| PFX generation (PKCS#12 MAC) | core/adcs | 🟡 Partial | `pfx.rs` (4KB) — basic structure, MAC calculation not standard-compliant |
| SCCM exploitation | core/sccm | 🟡 Partial | `mod.rs` (17KB) — types/stubs exist, no real WMI/HTTP interaction |
| MSSQL client (TDS protocol) | core/mssql | 🟡 Partial | `mod.rs` (41KB), `tds.rs` (7KB), `auth.rs` (7KB) exist — need live TDS validation |
| MSSQL linked server crawling | crawler | 🟡 Partial | `mssql_links.rs` (7KB) — depends on MSSQL client completion |
| Cross-forest trust abuse | crawler | 🔴 Missing | `interrealm.rs` (9KB) + `foreign.rs` (4KB) exist but no SID History / inter-realm TGT forging |
| Interactive TUI with live graph | cli | 🔴 Missing | Listed in README roadmap, no code exists |
| Plugin system for custom modules | core | 🔴 Missing | Listed in README roadmap, no code exists |
| C2 integration (Cobalt Strike / Sliver) | core | 🔴 Missing | Listed in README roadmap, no code exists |
| GPP password decryption (live SMB fetch) | core | 🟡 Partial | `crypto/` directory exists but live GPP XML fetch from SYSVOL needs verification |
| LAPS password reading (live) | reaper | 🟡 Partial | `laps.rs` (5KB) — LDAP query exists, v2 LAPS (encrypted) decryption unverified |
| Unit tests | tests | 🔴 Minimal | Only `tests/fixtures/` and `tests/integration/` directories exist |
| Integration tests | tests | 🔴 Minimal | Directory exists but no test files visible in listing |

***

## Prioritized Implementation Roadmap

### Phase 1 — 🔴 P0: Critical Protocol Fixes (Week 1-2)

These are the foundation. Everything else depends on correct protocol-level operations.

#### 1.1 DCSync via DRSR — Fix Live RPC Orchestration

**File:** `crates/overthrone-forge/src/dcsync_user.rs`
**File:** `crates/overthrone-core/src/proto/drsr.rs`

**What's broken:**
- Session key derivation uses MD4(password) instead of the NTLMSSP session base key from SMB auth
- DRSBind response parsing uses hardcoded offsets (bytes 24-44) instead of proper NDR decoding
- DRSGetNCChanges request is missing required DSNAME structure, ulFlags, EXOP_REPL_OBJ
- Response parser uses heuristic ATTID scanning instead of prefix table + NDR pointer chains

**What to fix (no new files needed):**
1. Add `session_key() -> Option<&[u8]>` method to `SmbSession` in `proto/smb.rs` to expose the NTLMSSP session base key
2. Rewrite `dcsync_user.rs`: Replace `derive_session_key()` with SMB session key extraction; fix `parse_drs_bind_response()` to walk NDR pointers for the context handle + DRS_EXTENSIONS_INT; fix `build_gnc_request()` to include proper DSNAME, USN_VECTOR, flags, and EXOP_REPL_OBJ; fix RPC bind to use correct frag_length calculation
3. Fix `drsr.rs`: Replace `scan_for_replentinflist()` heuristic with proper NDR-aware parsing using the SCHEMA_PREFIX_TABLE from the response

**Effort:** ~3 days

#### 1.2 NTLM Relay — Real Protocol Handlers

**File:** `crates/overthrone-relay/src/relay.rs`
**New files needed:** `smb_relay.rs`, `http_relay.rs`, `ldap_relay.rs`

**What's broken:** The 42KB `relay.rs` has the types, state machine, and session tracking, but the actual `relay_smb()`, `relay_http()`, and `relay_ldap()` methods log a message and return Ok. No TCP listener, no NTLM message forwarding, no target connection.

**What to implement:**
1. **`smb_relay.rs`** — SMB2 Negotiate → NTLM Negotiate extraction → Forward to target → Challenge relay → Authenticate relay → Authenticated session reuse for command execution via named pipe
2. **`http_relay.rs`** — HTTP 401/NTLM WWW-Authenticate listener → Extract NTLM Type 1 from client → Forward to target HTTP endpoint → Relay Type 2 challenge back → Forward Type 3 → Execute authenticated action
3. **`ldap_relay.rs`** — LDAP bind interception → NTLM bind extraction → Forward to target LDAP → Relay challenge → Forward auth → Use authenticated session for LDAP operations (add user, modify ACL)
4. Update `relay.rs` to wire these handlers into the existing `NtlmRelay` state machine, use the existing `RelaySession` tracking

**Effort:** ~5 days

#### 1.3 MSSQL TDS Client — Live Validation

**File:** `crates/overthrone-core/src/mssql/mod.rs` (41KB)
**File:** `crates/overthrone-core/src/mssql/tds.rs` (7KB)
**File:** `crates/overthrone-core/src/mssql/auth.rs` (7KB)

**What exists:** Types, TDS message framing, SQL auth login packet construction.

**What to verify/fix:**
1. TDS PRELOGIN handshake (version negotiation, encryption negotiation)
2. TDS LOGIN7 packet with NTLMSSP authentication (for domain accounts)
3. SQL batch request/response parsing (column metadata, row tokens, done tokens)
4. `xp_cmdshell` enable/execute flow
5. Linked server enumeration via `sp_linkedservers`

**Effort:** ~3 days

***

### Phase 2 — 🟠 P1: ADCS Attack Chain (Week 2-3)

Per the existing ADCS enhancement plan:

#### 2.1 PFX Export MAC Fix

**File:** `crates/overthrone-core/src/adcs/pfx.rs` (4KB)

The current PFX generation produces a basic PKCS#12 container but the MAC (Message Authentication Code) is not standard-compliant, making the PFX unimportable by Windows `certutil` or Chrome.

**Fix:** Replace the custom MAC with standard PKCS#12 MAC using `sha1(password_bytes || mac_salt || iteration_count)` per PKCS#12 spec, or integrate a mature Rust PKCS#12 crate.

**Effort:** ~1 day

#### 2.2 ADCS ESC1 — Full CSR + Web Enrollment Chain

**Files:** `crates/overthrone-core/src/adcs/csr.rs`, `web_enrollment.rs`, `mod.rs`

Code exists (18KB CSR builder, 21KB web enrollment client) but needs end-to-end validation:
1. RSA key generation → PKCS#10 CSR with SAN (Subject Alternative Name) attribute → DER encode → Base64
2. HTTP POST to `http://<CA>/certsrv/certfnsh.asp` with NTLM auth
3. Parse certificate response (DER/PEM extraction from HTML)
4. Bundle into PFX with the fixed PFX module
5. Wire into `mod.rs` `request_certificate_esc1()` — replace any remaining mock return paths

**Effort:** ~2 days

#### 2.3 ADCS ESC4 — Template ACL Modification via LDAP

**File:** `crates/overthrone-core/src/adcs/esc4.rs` (5KB)

Currently detection-only. Need to add:
1. LDAP modify operation on `ntSecurityDescriptor` attribute of certificate template
2. Add `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` to `msPKI-Certificate-Name-Flag`
3. Rollback mechanism (save original ACL, restore on cleanup)
4. Integrate with `overthrone-forge/src/cleanup.rs` for automated rollback tracking

**Effort:** ~2 days

#### 2.4 ADCS ESC5 — CA Config Modification

**File:** `crates/overthrone-core/src/adcs/esc5.rs` (5KB)

Requires remote registry write to set `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on the CA. Leverage the existing `proto/registry.rs` (33KB) which already implements MS-RRP (Remote Registry Protocol).

**Effort:** ~1 day

#### 2.5 ADCS ESC7 — CA Permission Modification

**File:** `crates/overthrone-core/src/adcs/esc7.rs` (4KB)

Need MS-ICPR RPC calls or DCOM to modify CA security descriptor. Most practical approach: generate PowerShell commands for the operator if DCOM implementation is too complex initially.

**Effort:** ~2 days

#### 2.6 ADCS ESC8 — NTLM Relay to Web Enrollment

**Files:** `crates/overthrone-relay/src/adcs_relay.rs` (12KB), depends on Phase 1.2 relay infrastructure

Wire the HTTP relay handler (from Phase 1.2) to the ADCS web enrollment endpoint. The `Esc8RelayTarget` struct exists; flesh it out to:
1. Accept relayed NTLM auth from the HTTP listener
2. Use authenticated session to submit CSR to `/certsrv/certfnsh.asp`
3. Return enrolled certificate
4. Bundle into PFX

**Effort:** ~2 days (after Phase 1.2 relay is done)

***

### Phase 3 — 🟡 P2: SCCM & Cross-Forest (Week 3-4)

#### 3.1 SCCM Exploitation

**File:** `crates/overthrone-core/src/sccm/mod.rs` (17KB)
**New files:** `sccm/wmi.rs`, `sccm/abuse.rs` per implementation plan

The existing 17KB `mod.rs` has types and trait definitions. Implementation needed:
1. **Site enumeration** via LDAP queries to `CN=System Management,CN=System,<base_dn>` — find SCCM site servers
2. **Collection enumeration** — WMI queries to `root\sms\site_<SITECODE>` for `SMS_Collection`
3. **Client push abuse** — Trigger SCCM client push installation to attacker-controlled host to capture NTLM credentials
4. **Application deployment abuse** — Create malicious application deployment targeting a collection
5. **NAA credential extraction** — Retrieve Network Access Account credentials from policy bodies

**Platform note:** WMI queries require Windows DCOM/WMI protocol implementation. For Linux, use the existing WMI exec path in `core/exec/wmiexec.rs` or implement HTTP-based SCCM AdminService API calls.

**Effort:** ~5 days

#### 3.2 Cross-Forest Trust Abuse

**Files:** `crates/overthrone-crawler/src/interrealm.rs` (9KB), `foreign.rs` (4KB)

Existing code handles trust mapping but needs:
1. **SID History injection** into golden tickets for cross-forest abuse (modify `overthrone-forge/src/golden.rs` to accept extra SIDs)
2. **Inter-realm TGT referral handling** in `core/proto/kerberos.rs`
3. **Foreign group membership** resolution using the existing `foreign.rs` as a base
4. **Selective authentication bypass** detection and exploitation

**Effort:** ~4 days

***

### Phase 4 — 🟢 P3: Testing & Quality (Week 4-5)

#### 4.1 Unit Tests

**Directory:** `tests/`

Currently minimal — only fixture and integration directories exist with no visible test files. Priority test areas:

| Test File | What to Test |
|-----------|-------------|
| `tests/unit/ntlm_test.rs` | NTLM hash computation, NTLMv2 challenge-response, session key derivation |
| `tests/unit/kerberos_test.rs` | TGT/TGS request construction, ticket parsing, PAC validation |
| `tests/unit/drsr_test.rs` | DRS_MSG_GETCHGREPLY parsing, ATTID decoding, secret decryption with known test vectors |
| `tests/unit/smb_test.rs` | SMB2 header construction, negotiate, session setup PDU building |
| `tests/unit/csr_test.rs` | PKCS#10 CSR generation, signing, DER encoding validation |
| `tests/unit/tds_test.rs` | TDS message framing, LOGIN7 construction, response token parsing |
| `tests/unit/graph_test.rs` | Attack graph building, Dijkstra shortest path, degree centrality |
| `tests/unit/golden_test.rs` | Golden ticket forging with known krbtgt hash, PAC construction |

**Effort:** ~4 days

#### 4.2 Integration Tests

| Test File | What to Test |
|-----------|-------------|
| `tests/integration/ldap_enum_test.rs` | Full LDAP enumeration against test DC |
| `tests/integration/kerberoast_test.rs` | End-to-end Kerberoast against lab SPN account |
| `tests/integration/dcsync_test.rs` | DCSync against test DC, verify extracted hashes |
| `tests/integration/relay_test.rs` | Full NTLM relay chain (SMB listener → target) |
| `tests/integration/adcs_test.rs` | Certificate enrollment against ADCS lab |

**Effort:** ~3 days (requires lab environment)

***

### Phase 5 — 🔵 P4: Advanced Features (Week 5-8)

#### 5.1 Interactive TUI with Live Attack Graph

**New file:** `crates/overthrone-cli/src/tui.rs`

Use `ratatui` (Rust TUI library) to build:
- Live node/edge rendering of the attack graph
- Real-time progress during autopwn execution
- Interactive node selection for manual path exploration
- Split pane: graph view + command output

**New dependency:** `ratatui = "0.28"`, `crossterm = "0.28"`

**Effort:** ~5 days

#### 5.2 Plugin System

**New files:** `crates/overthrone-core/src/plugin/mod.rs`, `plugin/loader.rs`

Implement a dynamic plugin system using Rust's `libloading` for `.so`/`.dll` plugins:
- Define `OverthronePlugin` trait with `name()`, `description()`, `execute()`, `cleanup()`
- Plugin discovery from `~/.overthrone/plugins/` directory
- Runtime loading and registration with the executor
- Plugin config via TOML

**New dependency:** `libloading = "0.8"`

**Effort:** ~4 days

#### 5.3 C2 Integration (Cobalt Strike / Sliver)

**New files:** `crates/overthrone-core/src/c2/mod.rs`, `c2/cobalt.rs`, `c2/sliver.rs`

- **Cobalt Strike:** External C2 spec — implement the `externalc2_start` listener protocol (TCP socket, read/write frames)
- **Sliver:** gRPC client to Sliver's operator API — generate implants, task beacons, receive output

**New dependency:** `tonic = "0.12"` (for gRPC), `prost = "0.13"`

**Effort:** ~6 days

***

## Complete Feature Matrix

| # | Feature | Crate | Priority | Status | Files to Modify | New Files | Effort |
|---|---------|-------|----------|--------|----------------|-----------|--------|
| 1 | DCSync DRSR live RPC | forge + core | 🔴 P0 | Partial | `dcsync_user.rs`, `drsr.rs`, `smb.rs` | None | 3d |
| 2 | NTLM Relay handlers | relay | 🔴 P0 | Partial | `relay.rs`, `lib.rs` | `smb_relay.rs`, `http_relay.rs`, `ldap_relay.rs` | 5d |
| 3 | MSSQL TDS live validation | core/mssql | 🔴 P0 | Partial | `mod.rs`, `tds.rs`, `auth.rs` | None | 3d |
| 4 | PFX MAC fix | core/adcs | 🟠 P1 | Partial | `pfx.rs` | None | 1d |
| 5 | ADCS ESC1 full chain | core/adcs | 🟠 P1 | Partial | `csr.rs`, `web_enrollment.rs`, `mod.rs` | None | 2d |
| 6 | ADCS ESC4 template ACL write | core/adcs | 🟠 P1 | Partial | `esc4.rs` | None | 2d |
| 7 | ADCS ESC5 CA config write | core/adcs | 🟠 P1 | Partial | `esc5.rs` | None | 1d |
| 8 | ADCS ESC7 CA permission abuse | core/adcs | 🟠 P1 | Partial | `esc7.rs` | None | 2d |
| 9 | ADCS ESC8 relay integration | relay | 🟠 P1 | Partial | `adcs_relay.rs` | None | 2d |
| 10 | SCCM exploitation | core/sccm | 🟡 P2 | Partial | `sccm/mod.rs` | `sccm/wmi.rs`, `sccm/abuse.rs` | 5d |
| 11 | Cross-forest trust abuse | crawler + forge | 🟡 P2 | Partial | `interrealm.rs`, `foreign.rs`, `golden.rs`, `kerberos.rs` | None | 4d |
| 12 | MSSQL linked server crawling | crawler | 🟡 P2 | Partial | `mssql_links.rs` | None | 1d |
| 13 | GPP password live SMB fetch | core | 🟡 P2 | Partial | `crypto/` module | None | 1d |
| 14 | LAPS v2 encrypted decryption | reaper | 🟡 P2 | Partial | `laps.rs` | None | 1d |
| 15 | Unit tests (8 test files) | tests | 🟢 P3 | Missing | None | 8 test files | 4d |
| 16 | Integration tests (5 test files) | tests | 🟢 P3 | Missing | None | 5 test files | 3d |
| 17 | Interactive TUI | cli | 🔵 P4 | Missing | None | `tui.rs` | 5d |
| 18 | Plugin system | core | 🔵 P4 | Missing | None | `plugin/mod.rs`, `plugin/loader.rs` | 4d |
| 19 | C2 integration | core | 🔵 P4 | Missing | None | `c2/mod.rs`, `c2/cobalt.rs`, `c2/sliver.rs` | 6d |

**Total estimated effort: ~55 engineering days**

***

## Dependency Additions Needed

The following dependencies should be added to the workspace `Cargo.toml`:

| Dependency | Version | Used For | Phase |
|------------|---------|----------|-------|
| `rsa` | 0.9 | RSA key generation for ADCS CSR | P1 |
| `x509-cert` | 0.2 | X.509 certificate parsing/generation | P1 |
| `pkcs8` | 0.10 | Private key encoding | P1 |
| `p12` | 0.6 | Standard PKCS#12/PFX generation | P1 |
| `ratatui` | 0.28 | Interactive TUI | P4 |
| `crossterm` | 0.28 | Terminal backend for TUI | P4 |
| `libloading` | 0.8 | Dynamic plugin loading | P4 |
| `tonic` | 0.12 | gRPC client for Sliver C2 | P4 |
| `prost` | 0.13 | Protocol Buffers for gRPC | P4 |

***

## Implementation Order (Recommended)

The optimal execution order accounts for dependency chains between features:

1. **SMB session key export** (prerequisite for DCSync and relay) — modify `proto/smb.rs`
2. **DCSync DRSR fixes** — `dcsync_user.rs` + `drsr.rs` (uses SMB session key)
3. **MSSQL TDS validation** — `mssql/` (independent, can parallel with #2)
4. **PFX MAC fix** — `adcs/pfx.rs` (prerequisite for all ADCS exploits)
5. **ADCS ESC1 full chain** — `adcs/csr.rs` + `web_enrollment.rs` (uses PFX)
6. **ADCS ESC4/ESC5/ESC7** — `adcs/esc4.rs`, `esc5.rs`, `esc7.rs` (independent of each other)
7. **NTLM Relay handlers** — `relay/` (complex, can parallel with ADCS)
8. **ADCS ESC8** — `adcs_relay.rs` (depends on relay handlers)
9. **SCCM exploitation** — `sccm/` (independent)
10. **Cross-forest trust abuse** — `crawler/` + `forge/golden.rs`
11. **Unit tests** — cover everything above
12. **Integration tests** — requires lab
13. **TUI, plugins, C2** — advanced features, lowest priority

***

## Key Architecture Decisions

### No New Crates Needed

The existing 9-crate workspace covers all planned features. New functionality fits within existing crates:
- Relay handlers → `overthrone-relay`
- SCCM/MSSQL → `overthrone-core`
- Cross-forest → `overthrone-crawler` + `overthrone-forge`
- TUI → `overthrone-cli`
- Plugins/C2 → `overthrone-core`

### SMB Session Key is the Linchpin

The single most impactful change is exposing the NTLMSSP session base key from `SmbSession`. This unlocks:
- Correct DCSync secret decryption
- NTLM relay session key forwarding
- Remote registry encrypted value decryption

This should be the absolute first thing implemented.

### ADCS Uses Existing LDAP + HTTP Infrastructure

All ADCS attacks leverage the existing LDAP client (`proto/ldap.rs`, 41KB) for enumeration and template modification, plus the existing HTTP client (`reqwest` dependency) for web enrollment. No new protocol implementations needed.

### Testing Strategy

Given this is a security tool that must work against live Active Directory, the testing strategy should be:
- **Unit tests** with known test vectors (NTLM hashes, Kerberos tickets, TDS packets from pcaps)
- **Integration tests** against a dedicated lab (Windows Server 2019/2022 DC, ADCS, MSSQL)
- **No mocking of protocol responses** — use real captured network data as fixtures in `tests/fixtures/`