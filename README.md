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

## What is this?

You know how in medieval warfare, taking a castle required siege engineers, scouts, cavalry, archers, sappers, and someone to open the gate from inside? Active Directory pentesting is exactly that, except the castle is a Fortune 500 company, the gate is a misconfigured Group Policy, and the "someone inside" is a service account with `Password123!` that hasn't been rotated since Windows Server 2008 was considered modern.

Overthrone is a full-spectrum AD red team framework that handles the entire kill chain — from "I have network access and a dream" to "I own every domain in this forest and here's a 47-page PDF proving it." Built in Rust because C2 frameworks deserve memory safety too, and because debugging use-after-free bugs during an engagement is how you develop trust issues (both the Active Directory kind and the personal kind).

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
│   ├── overthrone-core       # The brain — LDAP, Kerberos, SMB, NTLM, DRSR, MSSQL, ADCS, graph engine, crypto, C2, plugins, exec
│   ├── overthrone-reaper     # Enumeration — finds everything AD will confess (users, groups, ACLs, LAPS, GPP, ADCS)
│   ├── overthrone-hunter     # Exploitation — Kerberoast, ASREPRoast, coercion, delegation abuse, ticket manipulation
│   ├── overthrone-crawler    # Cross-domain — trust mapping, inter-realm tickets, SID filtering, foreign LDAP, MSSQL links
│   ├── overthrone-forge      # Persistence — Golden/Silver/Diamond tickets, DCSync, Shadow Creds, ACL backdoors, cleanup
│   ├── overthrone-pilot      # The autopilot — autonomous "hold my beer" mode with adaptive planning and wizard
│   ├── overthrone-relay      # NTLM relay — poisoning, responder, ADCS relay. The man-in-the-middle crate.
│   ├── overthrone-scribe     # Reporting — turns carnage into compliance documents (Markdown, PDF, JSON)
│   └── overthrone-cli        # The CLI + TUI + interactive REPL shell — where you type things and thrones fall
```

## The Crate Breakdown

Here's what's inside the box. Every module. Every protocol. Every hilarious amount of Rust the borrow checker screamed at us about. The table below is the **complete inventory** of what each crate actually does — no marketing fluff, no "coming soon" handwaving.

| Crate | Codename | What It Does | The Honest Truth |
|---|---|---|---|
| `overthrone-core` | The Absolute Unit | Protocol engine (LDAP, Kerberos, SMB, NTLM, MS-DRSR, MSSQL, DNS, Registry, PKINIT), attack graph with Dijkstra pathfinding, port scanner, full ADCS exploitation (ESC2-ESC8), crypto primitives (AES-CTS, RC4, HMAC, MD4, DPAPI, ticket crypto, GPP decryption), C2 integration (Sliver, Havoc, Cobalt Strike), plugin system (native DLL + WASM via wasmtime), remote execution (PsExec, SmbExec, WmiExec, WinRM, AtExec), interactive shell abstraction, secretsdump, RID cycling | The absolute unit that ate the gym. Every protocol is real — 56KB of Kerberos, 56KB of SMB, 43KB of LDAP, 50KB of secretsdump. The crypto stubs that used to be one-line doc comments cosplaying as code? Gone. Implemented. The borrow checker needed therapy after this one. |
| `overthrone-reaper` | The Collector | AD enumeration — users, groups, computers, ACLs, delegations, GPOs, OUs, SPNs, trusts, LAPS (v1 plaintext + v2 encrypted via DPAPI), GPP password decryption, MSSQL instances, ADCS template enumeration, BloodHound JSON export, CSV export | BloodHound's data collection arc but without Neo4j eating 4GB of RAM for breakfast. LAPS v2 encrypted now actually decrypts thanks to the DPAPI module finally existing. The long-awaited reunion happened. There were tears. |
| `overthrone-hunter` | The Overachiever | Kerberoasting, AS-REP roasting, auth coercion (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EFSRPC), RBCD abuse, constrained/unconstrained delegation exploitation, ticket manipulation (.kirbi/.ccache conversion), inline hash cracking with embedded wordlist + rayon parallelism | The crate that did all its homework, extra credit, and the teacher's homework too. Zero stubs. Zero placeholders. Every attack works. This crate graduated top of its class and then helped the other crates pass their finals. |
| `overthrone-crawler` | The Explorer | Cross-domain trust mapping, inter-realm TGT forging, SID filter analysis, PAM trust detection, MSSQL linked server crawling, **foreign trust LDAP enumeration** (users, groups, computers, SPNs, ACLs across trust boundaries), cross-domain escalation planning | Used to have 5 functions that all returned empty with "LDAP not yet implemented." Now `foreign.rs` is 25KB of real cross-trust LDAP queries. The procrastination era is over. Welcome to the productivity arc. |
| `overthrone-forge` | The Blacksmith | Golden/Silver/Diamond ticket forging with full PAC construction, DCSync per-user extraction via MS-DRSR, Shadow Credentials (msDS-KeyCredentialLink + PKINIT auth), ACL backdoors via DACL modification, Skeleton Key orchestration via SMB/SVCCTL, DSRM backdoor via remote registry, forensic cleanup for all persistence mechanisms, ticket validation | Golden Tickets? Forged. Silver Tickets? Minted. Diamond Tickets? Polished. Shadow Credentials? Actually works now — PKINIT has real RSA signing and DH key exchange instead of "placeholder PEM structures." The chocolate key became a real key. |
| `overthrone-pilot` | The Strategist | Autonomous attack planning from graph data, step-by-step execution with rollback, adaptive strategy based on runtime results, goal-based planning ("get DA" → resolve path), YAML playbook engine, interactive wizard mode, full autopwn orchestration connecting enum → graph → exploit → persist → report | The "hold my beer" engine. The executor alone is a terrifying 90KB single file. It plans, it adapts, it executes, it cleans up. If this crate were a person, it would be the one friend who organizes your entire vacation and also drives. |
| `overthrone-relay` | The Interceptor | NTLM relay engine (SMB→LDAP, HTTP→SMB, mix and match), LLMNR/NBT-NS/mDNS poisoner, network poisoner with stealth controls, ADCS-specific relay (ESC8) | Born complete. Zero stubs since day one. Responder.py walked so this crate could sprint. In Rust. Without the GIL. The overachiever sibling of overthrone-hunter. |
| `overthrone-scribe` | The Chronicler | Report generation — Markdown, JSON, PDF renderer. MITRE ATT&CK mapping, mitigation recommendations, attack narrative prose, session recording | Turns "I hacked everything" into "here's why you should pay us." All three formats work. Yes, including PDF now. The scribe and the CLI finally got couples therapy. |
| `overthrone-cli` | The Interface | CLI binary with Clap subcommands, interactive REPL shell with rustyline (command completion, history, context-aware prompts), TUI with ratatui (live attack graph visualization, session panels, logs), wizard mode, doctor command, autopwn, banner that took way too long to make | The interactive shell alone is 107KB. The commands implementation is 78KB. The main.rs is 68KB. We spent more time on terminal aesthetics than we'd like to admit. The banner ASCII art is *chef's kiss*. |

### The Crate Report Card

Because every crate deserves honest feedback. Even the ones that already know they're perfect.

```
overthrone-core     █████████████████████░  ~95%  The remaining 5% is ADCS ESC1/ESC6 and WASM quirks
overthrone-reaper   ██████████████████████  ~98%  DPAPI arrived. LAPS v2 decrypts. Life is good.
overthrone-hunter   ██████████████████████  100%  The overachiever. No notes. Perfect attendance.
overthrone-crawler  █████████████████████░  ~95%  foreign.rs graduated from empty to 25KB. Proud parent moment.
overthrone-forge    █████████████████████░  ~96%  Shadow Creds PKINIT is real now. Diamond tickets shine.
overthrone-pilot    █████████████████████░  ~95%  90KB executor. The "hold my beer" engine runs.
overthrone-relay    ██████████████████████  100%  Born yesterday, already complete. Prodigy crate.
overthrone-scribe   █████████████████████░  ~97%  PDF works. Markdown works. JSON works. What a time to be alive.
overthrone-cli      █████████████████████░  ~93%  107KB interactive shell. Some wiring left (TUI crawler, C2 deploy).
```

## What's Still Cooking (The Remaining Backlog)

Every project has a backlog. Ours is smaller than it used to be, which is either a sign of progress or a sign that we lowered our standards. (It's progress. Probably.)

| What | Where | Status | The Excuse |
|---|---|---|---|
| **ADCS ESC1** | `core/src/adcs/` | ❌ No file exists | The most common ADCS attack vector. We somehow implemented ESC2 through ESC8 but forgot the main character. Like filming all the Marvel movies but skipping Iron Man. We'll get to it. |
| **ADCS ESC6** | `core/src/adcs/` | ❌ No file exists | `EDITF_ATTRIBUTESUBJECTALTNAME2` flag check on the CA. We know the flag name. We know what it does. We just haven't written the code. The spirit is willing but the fingers are elsewhere. |
| **WASM plugin state persistence** | `core/src/plugin/loader.rs` | ⚠️ Known issue | `execute_command()` re-creates a new Store every call, so plugin state gets wiped between commands. Your WASM plugin has amnesia. Every execution is its first day at work. |
| **WASM manifest parsing** | `core/src/plugin/loader.rs` | ⚠️ Stub | `extract_wasm_manifest()` returns `None`. Custom section parsing isn't implemented. The manifest is in there somewhere. We just can't read it. |
| **WASM memory allocation** | `core/src/plugin/loader.rs` | ⚠️ Hardcoded | Uses fixed offset 1024 for writing to WASM memory instead of calling a plugin allocator. Will work great until your command string is longer than "hello." |
| **Native plugin free()** | `core/src/plugin/loader.rs` | ⚠️ Compatibility | Calls libc `free()` on plugin result strings. Works if the plugin uses C allocator. Rust plugins using `Box`? That's a segfault waiting to happen. |
| **CLI PDF output wiring** | `cli/src/commands_impl.rs` | ⚠️ Miscommunication | Scribe has a full PDF renderer. CLI doesn't call it. They're in the same workspace. They share the same Cargo.toml. They've never spoken. We're scheduling a team building exercise. |
| **C2 implant deploy CLI** | `cli/src/main.rs` | ⚠️ TODO comment | "Construct ImplantRequest and wire to C2Manager.deploy_implant()" — the TODO is doing its best impression of an implementation. |
| **TUI crawler integration** | `cli/src/tui/runner.rs` | ⚠️ Unwired | "TODO: Integrate actual crawler when available." The crawler has been available. It's one crate over. They should get lunch sometime. |
| **WinRM Windows output** | `core/src/exec/winrm/windows.rs` | ⚠️ Half-done | Commands execute perfectly. Output collection returns a placeholder string. Schrödinger's remote execution — the command ran, but did it? |
| **Integration tests** | Project-wide | ❌ Missing | Unit tests and property-based tests exist. But nobody has actually tested this against a real lab DC. "It compiles" is not a test strategy, no matter how much Rust evangelists claim otherwise. |

## Features

### Enumeration (overthrone-reaper)

The "ask nicely and receive everything" phase. Active Directory is the most oversharing protocol since your aunt discovered Facebook.

| Feature | What it finds | Status |
|---|---|---|
| **Full LDAP enumeration** | Every user, computer, group, OU, and GPO in the domain. AD is surprisingly chatty with authenticated users. It's like a bartender who tells you everyone's secrets after one drink. | ✅ Done |
| **Kerberoastable accounts** | Service accounts with SPNs. These are the ones with passwords that haven't been changed since someone thought "qwerty123" was secure. | ✅ Done |
| **AS-REP roastable accounts** | Accounts that don't require pre-authentication. Someone literally unchecked a security checkbox. On purpose. In production. | ✅ Done |
| **Domain trusts** | Parent/child, cross-forest, bidirectional. The map of "who trusts whom" and more importantly, "who shouldn't." | ✅ Done |
| **ACL analysis** | GenericAll, WriteDACL, WriteOwner — the holy trinity of "this service account can do WHAT?" | ✅ Done |
| **Delegation discovery** | Unconstrained, constrained, resource-based. Delegation is AD's way of saying "I trust this computer to impersonate anyone." | ✅ Done |
| **Password policy** | Lockout thresholds, complexity requirements, history. Know the rules before you break them. | ✅ Done |
| **LAPS discovery** | LAPS v1 (plaintext ms-Mcs-AdmPwd) and LAPS v2 — including the encrypted variant (msLAPS-EncryptedPassword) via DPAPI/AES-256-GCM decryption. The DPAPI module finally exists. Hallelujah. | ✅ Full (v1 + v2 encrypted) |
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
| **Auth Coercion** | PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce — force machines to authenticate to you. The DC does this willingly. Microsoft considers this "working as intended." | ✅ Full (5 techniques) |
| **RBCD Abuse** | Create machine account + modify msDS-AllowedToActOnBehalfOfOtherIdentity + S4U2Self/S4U2Proxy chain. The attack with the longest name and the shortest time-to-DA. | ✅ Full |
| **Constrained Delegation** | S4U2Self + S4U2Proxy to impersonate users to specific services. Microsoft: "You can only impersonate to these services." Attackers: "What about these other services?" | ✅ Full |
| **Unconstrained Delegation** | Steal TGTs from anyone who authenticates to a compromised machine. It's always the print server. Always. | ✅ Full |
| **Inline Hash Cracking** | Embedded top-10K wordlist (zstd compressed), rayon parallel cracking, rule engine (leet, append year/digits, capitalize), hashcat subprocess fallback. | ✅ Full |
| **Ticket Manipulation** | Request, cache, convert between .kirbi and .ccache formats. Tickets are the currency of AD. This module is the money printer. | ✅ Full |

### Attack Graph (overthrone-core)

BloodHound rebuilt in Rust without the Neo4j dependency. Maps every relationship in the domain and finds the shortest path to making the blue team update their resumes.

| Feature | Details | Status |
|---|---|---|
| **Directed graph** | Nodes (users, computers, groups, domains) and edges (MemberOf, AdminTo, HasSession, GenericAll, etc.) — LinkedIn for attack paths. | ✅ Full (petgraph) |
| **Shortest path** | Dijkstra with weighted edges — `MemberOf` is free, `AdminTo` costs 1, `HasSpn` costs 5 (offline cracking). Finds the path of least resistance. Just like a real attacker. Just like water. | ✅ Full |
| **Path to DA** | Finds every shortest path from a compromised user to Domain Admins. Usually shorter than you'd expect. Usually terrifyingly short. | ✅ Full |
| **High-value targets** | Auto-identifies Domain Admins, Enterprise Admins, Schema Admins, KRBTGT, DC computer accounts. The "if you compromise these, the game is over" list. | ✅ Full |
| **Kerberoast reachability** | "From user X, which Kerberoastable accounts can I reach, and how?" — it's a shopping list for your GPU. | ✅ Full |
| **Delegation reachability** | "From user X, which unconstrained delegation machines are reachable?" (Spoiler: it's the print server.) | ✅ Full |
| **JSON export** | Full graph export for D3.js, Cytoscape, or your visualization tool of choice. Clients love graphs that look like conspiracy boards. | ✅ Full |
| **Degree centrality** | Find the nodes with the most connections. Either Domain Admins or the intern's test account that somehow has GenericAll on everything. | ✅ Full |

### NTLM Relay & Poisoning (overthrone-relay)

Born complete. Zero stubs. The prodigy crate that showed up on day one and said "I'm not here to play, I'm here to win."

| Feature | Details | Status |
|---|---|---|
| **NTLM Relay Engine** | Full relay — capture NTLM auth from one protocol, replay to another. SMB → LDAP, HTTP → SMB, mix and match like a deadly cocktail. | ✅ Full |
| **LLMNR/NBT-NS/mDNS Poisoner** | Respond to broadcast name resolution. "Who is FILESERVER?" "Me. I'm FILESERVER now." Identity theft, but for computers. | ✅ Full |
| **Network Poisoner** | Decides when to poison, what to poison, and how aggressively — while avoiding detection. Subtlety is an art form. | ✅ Full |
| **ADCS Relay (ESC8)** | Relay NTLM auth to AD Certificate Services web enrollment. Get a certificate as the victim. Certificates: the new hashes. | ✅ Full |

### Persistence (overthrone-forge)

Taking the throne is easy. Keeping it is an art form. This crate welds the crown to your head.

| Technique | What it does | Status |
|---|---|---|
| **DCSync** | Replicate credentials from the DC using MS-DRSR. Get every hash in the domain. The CEO's. The intern's. The service account from 2009 nobody remembers creating. | ✅ Full |
| **Golden Ticket** | Forge a TGT signed with the KRBTGT hash. Be any user. Access anything. The Willy Wonka golden ticket, except the factory is Active Directory. | ✅ Full (with PAC construction) |
| **Silver Ticket** | Forge a TGS for a specific service. Stealthier than Golden — no DC interaction needed. | ✅ Full |
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
| **ESC1** | Enrollee supplies subject / SAN in request | ❌ Not implemented | The most common ADCS attack. We skipped the main character. Iron Man is missing from the MCU. We know. |
| **ESC2** | Any purpose EKU + enrollee supplies subject | ✅ Implemented | Any Purpose certificates exploited via enrollment request manipulation. The "I can be anything" certificate. |
| **ESC3** | Enrollment agent + second template abuse | ✅ Implemented | Two-step: get enrollment agent cert, then request cert as victim. The buddy system of exploitation. |
| **ESC4** | Vulnerable template ACLs → modify to ESC1 | ✅ Implemented | Modify template permissions, then exploit. If you can write the rules, you can break the rules. |
| **ESC5** | Vulnerable PKI object permissions | ✅ Implemented | Abuse permissions on PKI infrastructure objects. |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | ❌ Not implemented | The CA flag check we forgot. Its name is longer than the code would be. |
| **ESC7** | CA access control abuse (ManageCA rights) | ✅ Implemented | CA permission manipulation. |
| **ESC8** | Web enrollment NTLM relay | ✅ Implemented | Full relay with the overthrone-relay crate integration. |

### Remote Execution (overthrone-core)

Six lateral movement methods. All implemented. The `todo!()` trio graduated.

| Method | Protocol | Status | Notes |
|---|---|---|---|
| **WinRM (Linux/macOS)** | WS-Management + NTLM | ✅ Full | Pure Rust WS-Man with NTLM auth. Create shell, execute, receive output, delete shell. Cross-platform perfection. |
| **WinRM (Windows)** | Win32 WSMan API | ⚠️ Mostly done | Commands execute via native Win32 API. Output collection still returns a placeholder string. The command runs. What it said is... a mystery. |
| **AtExec** | ATSVC over SMB | ✅ Full | Scheduled task creation via named pipe. "Task Scheduler is a feature, not a vulnerability." |
| **PsExec** | DCE/RPC + SMB | ✅ Full | Real DCE/RPC bind packet building, service creation, payload upload to ADMIN$, execution, cleanup. The sports car now has a steering wheel. |
| **SmbExec** | SCM over SMB | ✅ Full | Service-based command execution via SMB named pipes. Clean, simple, effective. |
| **WmiExec** | DCOM/WMI | ✅ Full | WMI-based semi-interactive command execution with output retrieval via SMB. |

### C2 Framework Integration (overthrone-core)

The C2 integration that went from "aspirational" to "actually works." Three backends, all with real HTTP clients, real auth flows, and real API calls.

| Framework | What It Does | Auth | Status |
|---|---|---|---|
| **Sliver** | Full C2Channel trait — sessions, beacons, exec, PowerShell, upload/download, assembly, BOF, shellcode inject, implant generation, listener management. Operator `.cfg` parsing with mTLS. | mTLS (certificate + CA from operator config) | ✅ Full |
| **Havoc** | Full C2Channel trait — Demon agent management, shell/PowerShell exec, upload/download, .NET assembly exec, BOF exec, shellcode inject, payload generation. Task polling with 5-min timeout. | Token or password auth (REST login endpoint) | ✅ Full |
| **Cobalt Strike** | Full C2Channel trait — beacon management, BOF execution, shellcode injection, payload generation. Aggressor-style REST API. | Bearer token or password auth | ✅ Full |

All three implement the complete `C2Channel` async trait: `connect`, `disconnect`, `list_sessions`, `get_session`, `exec_command`, `exec_powershell`, `upload_file`, `download_file`, `execute_assembly`, `execute_bof`, `shellcode_inject`, `deploy_implant`, `list_listeners`, `server_info`. The trait system is legitimately well-designed. The water is connected now.

### Crypto Layer (overthrone-core)

The layer that used to be the "Empty Files Hall of Shame." The shame has been resolved. The five one-line doc comments are now real implementations.

| Module | What It Does | Status |
|---|---|---|
| **AES-CTS** | AES256-CTS-HMAC-SHA1 for Kerberos etype 17/18. The thing that makes modern tickets work. | ✅ Full |
| **RC4** | RC4 encryption for Kerberos etype 23. The crypto equivalent of a screen door on a submarine, but AD still uses it everywhere. | ✅ Full |
| **HMAC** | HMAC utilities for ticket validation and integrity checking. | ✅ Full |
| **MD4** | MD4 hash for NTLM password hashing. The algorithm from 1990 that refuses to die, much like NTLM itself. | ✅ Full |
| **Ticket Crypto** | Ticket forging primitives — encryption, PAC signing, checksum computation. The mathematical foundation of ticket forging. | ✅ Full |
| **DPAPI** | LAPS v2 encrypted blob parsing, AES-256-GCM decryption, HMAC-SHA512 key derivation. With property-based tests using `proptest`. The module that doesn't exist? It exists now. | ✅ Full (with tests) |
| **GPP** | Group Policy Preferences cpassword AES decryption. Microsoft published the key. We just use it. | ✅ Full |
| **Cracker** | Offline hash cracking engine — embedded wordlist, rayon parallel processing, rule engine. | ✅ Full |

### Plugin System (overthrone-core)

| Component | Status | Notes |
|---|---|---|
| **Plugin Trait** | ✅ Full | Complete plugin API: manifest, capabilities, events, command execution. |
| **Native DLL Loading** | ✅ Full | `libloading`-based FFI with API version checking, manifest JSON parsing, function pointer caching. |
| **Built-in Example** | ✅ Full | SmartSpray plugin with lockout avoidance. A complete working example that actually spray-attacks responsibly. |
| **WASM Plugin Runtime** | ⚠️ Functional with quirks | Wasmtime engine, module compilation, host function linking (`env.log`, `env.graph_add_node`, `env.graph_add_edge`). Plugins load and execute. State doesn't persist between calls (re-creates Store). Manifest parsing returns None. The engine is running, the memory management needs a tune-up. |

### Autonomous Planning (overthrone-pilot)

The "I'll hack it myself" engine.

| Feature | Status |
|---|---|
| **Attack Planner** | ✅ Plans multi-step attack chains from enumeration data |
| **Step Executor** | ✅ Executes each planned step by calling Hunter/Forge/Reaper. 90KB of execution logic. |
| **Adaptive Strategy** | ✅ Adjusts plan on-the-fly based on what succeeds and fails |
| **Goal System** | ✅ Target DA, Enterprise Admin, specific user, specific host |
| **Playbooks** | ✅ Pre-built YAML attack sequences for common scenarios |
| **Wizard Mode** | ✅ Interactive guided mode for manual control with autopilot assist |
| **AutoPwn Runner** | ✅ Full engagement orchestrator: enum → graph → exploit → persist → report |

### Reporting (overthrone-scribe)

The difference between a penetration test and a crime is paperwork. This crate does the paperwork.

| Format | Status | Notes |
|---|---|---|
| **Markdown** | ✅ Works | Technical report with findings, attack paths, and mitigations. For the team that has to fix things. |
| **JSON** | ✅ Works | Machine-readable for integration with SIEMs, ticketing systems, or your "how screwed are we" dashboard. |
| **PDF** | ✅ Works | Executive summary for people who think "Domain Admin" is a job title. Custom PDF renderer. |

Every report includes: findings with severity, full attack paths with hop-by-hop details, affected assets, MITRE ATT&CK mappings, remediation steps, mitigation recommendations, and attack narrative prose. Because "GenericAll on the Domain Object via nested group membership through a misconfigured ACE" means nothing to a CISO. "Anyone in marketing can become Domain Admin in 3 steps" does.

## Edge Types & Cost Model

The attack graph uses weighted edges. Lower cost = easier to exploit. The pathfinder minimizes total cost — finding the path of least resistance. Just like a real attacker. Just like electricity. Just like that one coworker who always finds the shortcut.

| Edge Type | Cost | Meaning |
|---|---|---|
| `MemberOf` | 0 | Group membership — free traversal, you already have it |
| `HasSidHistory` | 0 | SID History — legacy identity, free impersonation |
| `Contains` | 0 | OU/GPO containment — structural relationship |
| `AdminTo` | 1 | Local admin — direct compromise |
| `DcSync` | 1 | Replication rights — game over |
| `GenericAll` | 1 | Full control — you are God (of this specific object) |
| `ForceChangePassword` | 1 | Reset their password — aggressive but effective |
| `Owns` | 1 | Object owner — can grant yourself anything |
| `WriteDacl` | 1 | Modify permissions — give yourself GenericAll |
| `WriteOwner` | 1 | Change owner — give yourself Owns |
| `AllowedToDelegate` | 1 | Constrained delegation — impersonate to target service |
| `AllowedToAct` | 1 | RBCD — sneakier delegation abuse |
| `HasSession` | 2 | Active session — credential theft opportunity |
| `GenericWrite` | 2 | Write attributes — targeted property abuse |
| `AddMembers` | 2 | Add to group — escalate via group membership |
| `ReadLapsPassword` | 2 | Read LAPS — plaintext local admin password |
| `ReadGmsaPassword` | 2 | Read gMSA — service account password blob |
| `CanRDP` | 3 | RDP access — interactive logon |
| `CanPSRemote` | 3 | PS Remoting — command execution |
| `ExecuteDCOM` | 3 | DCOM execution — Excel goes brrr |
| `SQLAdmin` | 3 | SQL Server admin — `xp_cmdshell` is a "feature" |
| `TrustedBy` | 4 | Domain trust — cross-domain, requires more setup |
| `HasSpn` | 5 | Kerberoastable — offline cracking required |
| `DontReqPreauth` | 5 | AS-REP roastable — offline cracking required |
| `Custom(*)` | 10 | Unknown/custom — high cost, manual analysis needed |

## Protocol Stack

What Overthrone speaks fluently. All implemented in pure Rust:

| Protocol | Used for |
|---|---|
| **LDAP/LDAPS** | Domain enumeration, user/group/GPO/trust queries, ACL reading. AD's diary. |
| **Kerberos** | Authentication, TGT/TGS requests, ticket forging, roasting, PKINIT. The three-headed dog of authentication. |
| **SMB 2/3** | File operations, share enumeration, lateral movement, PtH. The universal remote of Windows networking. |
| **NTLM** | NT hash computation, NTLMv2 challenge-response, Pass-the-Hash. The protocol that refuses to die. |
| **MS-DRSR** | DCSync — replicating credentials via DRS RPC. Politely asking the DC for all credentials. |
| **MS-SAMR/RID** | SAM Remote — RID cycling, SID brute-force enumeration |
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

For the trust-no-one crowd (respect — you're pentesters, paranoia is a job requirement):

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
| **WSL** | Full support | Best of both worlds — Windows target, Linux attacker, one machine. |

## Usage

### Quick Start — Autopwn

For when you want to go from "I have creds" to "I own the domain" in one command:

```bash
# Full form
overthrone autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Shorthand — for every occasion
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'
```

That's it. Overthrone enumerates, builds the attack graph, finds the shortest path to DA, executes it, DCSyncs, and generates a report. Go get coffee. Come back to a report that explains how you own the entire forest.

### Manual Mode

```bash
# Step 1: Enumerate everything
ovt enum --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Step 2: Build and query the attack graph
ovt graph --path-to-da jsmith
ovt graph --shortest-path jsmith "Domain Admins"
ovt graph --kerberoastable-from jsmith
ovt graph --high-value-targets
ovt graph --export graph.json

# Step 3: Kerberoast
ovt roast kerberoast --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'
ovt roast asrep --dc 10.10.10.1 --domain corp.local -u jsmith

# Step 4: Spray (carefully)
ovt spray --dc 10.10.10.1 --domain corp.local --users users.txt --password 'Winter2026!'

# Step 5: Lateral movement
ovt move pth --target 10.10.10.50 --domain corp.local -u admin \
  --hash aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
ovt move exec --target 10.10.10.50 --command "whoami /all"

# Step 6: Persist
ovt forge dcsync --dc 10.10.10.1 --domain corp.local -u dadmin -p 'G0tcha!'
ovt forge golden --krbtgt-hash <hash> --domain corp.local --domain-sid S-1-5-21-...
ovt forge silver --service-hash <hash> --service cifs/dc01.corp.local --domain corp.local

# Step 7: Report
ovt report --format markdown --output engagement-report.md
ovt report --format json --output findings.json
ovt report --format pdf --output executive-summary.pdf
```

### Command Reference

#### `ovt enum` — Enumeration

```bash
ovt enum [OPTIONS]
```

| Flag | Short | Required | Description |
|---|---|---|---|
| `--dc` | `-d` | Yes | Domain Controller IP or hostname |
| `--domain` | | Yes | Target domain (e.g., `corp.local`) |
| `--username` | `-u` | Yes | Domain username |
| `--password` | `-p` | Yes* | Password (*or use `--hash`) |
| `--hash` | | No | NT hash for Pass-the-Hash authentication |
| `--ldaps` | | No | Use LDAP over SSL (port 636) |
| `--output` | `-o` | No | Save enumeration to JSON file |
| `--full` | | No | Include ACL enumeration (slower but finds the juicy stuff) |

#### `ovt graph` — Attack Graph

| Subcommand | Description |
|---|---|
| `--path-to-da <user>` | Find shortest paths from user to Domain Admins |
| `--shortest-path <src> <dst>` | Find shortest path between any two nodes |
| `--kerberoastable-from <user>` | Find reachable Kerberoastable accounts |
| `--unconstrained-from <user>` | Find reachable unconstrained delegation targets |
| `--high-value-targets` | List all high-value targets with incoming edge counts |
| `--stats` | Print graph statistics |
| `--export <file.json>` | Export full graph as JSON |

#### `ovt roast` — Kerberoasting & AS-REP Roasting

```bash
ovt roast [kerberoast|asrep] [OPTIONS]
```

| Flag | Description |
|---|---|
| `kerberoast` | Request TGS tickets for all SPN accounts |
| `asrep` | Request AS-REP for accounts without pre-auth |
| `--format` | Output format: `hashcat` (default) or `john` |
| `-o` | Save hashes to file |

#### `ovt forge` — Persistence

```bash
ovt forge [dcsync|golden|silver|diamond] [OPTIONS]
```

| Subcommand | What it does |
|---|---|
| `dcsync` | Replicate all hashes from the DC via MS-DRSR |
| `golden` | Forge a Golden Ticket (needs KRBTGT hash) |
| `silver` | Forge a Silver Ticket (needs service account hash) |
| `diamond` | Forge a Diamond Ticket (modify legit TGT PAC) |

#### `ovt report` — Reporting

```bash
ovt report [OPTIONS]
```

| Flag | Description |
|---|---|
| `--format` | `markdown`, `json`, or `pdf` |
| `--output`, `-o` | Output file path |
| `--template` | Custom report template |
| `--executive` | Include executive summary |

## Examples

### Scenario 1: "I just got a foothold"

```bash
# Enumerate
ovt enum --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Phished123!' --full

# Find paths to DA
ovt graph --path-to-da jsmith
# Output: 3 hops. The CISO will need to sit down.

# Kerberoast the service account in the path
ovt roast kerberoast --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Phished123!'
# Crack: hashcat -m 13100 kerberoast.txt wordlist.txt
# Got: SVC-BACKUP:Backup2019!

# PtH to DC
ovt move pth --target dc01.corp.local --domain corp.local -u SVC-BACKUP --hash <hash>

# DCSync everything
ovt forge dcsync --dc 10.10.10.1 --domain corp.local -u SVC-BACKUP -p 'Backup2019!'

# Report
ovt report --format markdown --executive -o corp-local-report.md
```

### Scenario 2: "Full autopwn, I have a meeting in an hour"

```bash
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'
# Go get coffee. Come back to: engagement-report.md
```

## FAQ

**Q: Is this legal?**
A: With explicit written authorization — absolutely. Without it — absolutely not. The difference between a pentester and a criminal is a signed document and a really good PowerPoint presentation.

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
A: Native DLL plugin loading works with a full Plugin trait. WASM plugins load and execute via wasmtime (with some quirks around state persistence). The workspace architecture makes adding new modules straightforward. PRs welcome.

**Q: What about the C2 integrations?**
A: They work now. Sliver (mTLS REST), Havoc (REST with auth), Cobalt Strike (Aggressor-style REST). Real HTTP clients, real API calls, real session management. The "aspirational code" era is over.

## Contributing

PRs welcome. Issues welcome. Memes about Active Directory misconfigurations are especially welcome. If your PR includes a pun in the commit message, it gets reviewed first.

## Star History

If you've read this far — all the way to the bottom of this README, past the crate report card, past the backlog table — you're legally obligated to star the repo. It's in the MIT license. (It's not in the MIT license. But it should be.)

**[Star this repo](https://github.com/Karmanya03/Overthrone)** — every star adds 0.001 damage to the attack graph.

## Disclaimer

This tool is for **authorized security testing only**. Using Overthrone against systems without explicit written permission is illegal, unethical, and will make your parents disappointed. The authors are not responsible for misuse.

Always:
- Get written authorization before testing
- Define scope and rules of engagement
- Don't break things you weren't asked to break
- Report everything you find, especially the embarrassing stuff
- Remember that somewhere, a sysadmin set `Password1` on a service account and hoped nobody would notice

## License

MIT — use it, modify it, learn from it, build on it. Just don't be evil with it.

***

<p align="center">
  <sub>Built with mass amounts of mass-produced instant coffee, mass amounts of Rust, and a personal grudge against misconfigured ACLs.</sub><br/>
  <sub>9 crates. Pure Rust protocols. Zero Python. One smbclient dependency. No regrets. (Some regrets.)</sub><br/>
  <sub>Every throne falls. The question is whether you find out from a pentester or from a ransomware note.</sub><br/>
  <sub>We prefer the first option. Your insurance company does too.</sub>
</p>
