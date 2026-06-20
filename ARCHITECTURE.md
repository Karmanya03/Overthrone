# Overthrone Architecture

The framework is split across 10 crates in a Rust workspace. Each crate owns a specific
phase of the attack lifecycle. They communicate through function calls (not IPC or
network — everything runs in-process). The CLI crate is the entry point; everything
else is a library it calls into.

There's no "core dispatcher service" or centralized event bus. The flow is:

```
CLI → pilot → [reaper, hunter, forge, relay] → core (protocols)
                                            → scribe (output)
```

The `overthrone-core` crate is the dependency of everything. Every other crate imports
it for protocol types, crypto primitives, and data structures. The CLI imports every
crate. The viewer is standalone (serves a web GUI, imports core for graph types).

---

## 1. Top-Level Crate Map

This is the big picture — every crate, its job, and who it talks to.

```mermaid
flowchart TB
    classDef cli fill:#6366f1,color:#fff,stroke:#4f46e5
    classDef orchestrator fill:#8b5cf6,color:#fff,stroke:#7c3aed
    classDef recon fill:#06b6d4,color:#fff,stroke:#0891b2
    classDef attack fill:#f59e0b,color:#000,stroke:#d97706
    classDef persistence fill:#10b981,color:#fff,stroke:#059669
    classDef output fill:#ec4899,color:#fff,stroke:#db2777
    classDef core fill:#ef4444,color:#fff,stroke:#dc2626
    classDef standalone fill:#64748b,color:#fff,stroke:#475569

    CLI["overthrone-cli"]
    PILOT["overthrone-pilot"]
    REAPER["overthrone-reaper"]
    HUNTER["overthrone-hunter"]
    CRAWLER["overthrone-crawler"]
    FORGE["overthrone-forge"]
    RELAY["overthrone-relay"]
    SCRIBE["overthrone-scribe"]
    CORE["overthrone-core"]
    VIEWER["overthrone-viewer"]

    CLI --> PILOT
    CLI --> REAPER
    CLI --> HUNTER
    CLI --> CRAWLER
    CLI --> FORGE
    CLI --> RELAY
    CLI --> SCRIBE
    CLI --> CORE

    PILOT --> REAPER
    PILOT --> CRAWLER
    PILOT --> HUNTER
    PILOT --> FORGE
    PILOT --> RELAY
    PILOT --> SCRIBE
    PILOT --> CORE

    REAPER --> CORE
    CRAWLER --> CORE
    HUNTER --> CORE
    FORGE --> CORE
    RELAY --> CORE

    VIEWER --> CORE

    class CLI cli
    class PILOT orchestrator
    class REAPER,CRAWLER recon
    class HUNTER,RELAY attack
    class FORGE persistence
    class SCRIBE output
    class CORE core
    class VIEWER standalone
```

Core is the dependency everyone shares. Pilot optionally orchestrates the others when
running in auto-pwn mode. CLI is the user's entry point. Viewer is a standalone web
server that only imports core for graph data types.

---

## 2. overthrone-core — The Absolute Unit

Core is the protocol engine. It has no dependencies on other Overthrone crates. Every
other crate depends on it. It owns the network protocols, crypto, attack graph, post-
exploitation modules, C2 integrations, and ADCS exploit logic.

### 2a. Module Map

Core has ~130 source files organized into subdirectories by domain:

```mermaid
flowchart LR
    subgraph proto["Proto — Network Protocols"]
        KRB["Kerberos<br/>TGT/TGS/FAST/PKINIT"]
        SMB["SMB2/3<br/>OPLOCK/Signing"]
        LDAP["LDAP/LDAPS<br/>Pagination"]
        NTLM["NTLM<br/>MIC Strip/DCE Strip"]
        DRSR["MS-DRSR<br/>DCSync"]
        MSSQL["MSSQL/TDS<br/>Linked Servers"]
        COERCE["Coerce<br/>Printer/Petitpotam/DFS"]
    end

    subgraph crypto["Crypto Primitives"]
        AES["AES-CTS<br/>etype 17/18"]
        RC4["RC4<br/>etype 23"]
        DPAPI["DPAPI<br/>LAPS v2 decrypt"]
        GPP["GPP<br/>cpassword decrypt"]
        CRACK["Cracker<br/>Hashcat + embedded"]
    end

    subgraph postex["Post-Exploitation"]
        EDR["EDR Bypass<br/>ntdll unhook/ETW kill"]
        CG["Credential Guard<br/>3-tier bypass"]
        SYS["Raw Syscalls<br/>asm! + DynamicStub"]
        DPAPIEXT["DPAPI Extract<br/>masterkey decrypt"]
        CARVER["File Carver<br/>docx/xlsx secrets"]
        SKEL["Skeleton Key<br/>LSASS patch DLL"]
    end

    subgraph exec["Remote Execution"]
        PSEXEC["PsExec<br/>SVCCTL pipe"]
        SMBEXEC["SmbExec<br/>temp service"]
        WMIEXEC["WmiExec<br/>DCOM/WMI"]
        WINRM["WinRM<br/>WSMan"]
        ATEXEC["AtExec<br/>scheduled task"]
    end

    subgraph adcs["ADCS Exploitation"]
        ESC1["ESC1 — SAN abuse"]
        ESC2_9["ESC2-9<br/>Agent/Policy/Relay"]
        ESC10_16["ESC10-16<br/>Mapping/PKI/Chain"]
        WEBENROLL["Web Enrollment<br/>CSR + PFX"]
    end

    subgraph c2["C2 Integrations"]
        SLIVER["Sliver<br/>mTLS REST"]
        HAVOC["Havoc<br/>Token auth"]
        CS["Cobalt Strike<br/>Aggressor REST"]
    end

    subgraph graph["Attack Graph"]
        BUILD["Graph Builder<br/>petgraph"]
        PATH["Pathfinder<br/>Dijkstra"]
        EDGE["Edge Types<br/>30+ BH variants"]
    end

    proto --> AES
    proto --> RC4
    ADCS --> WEBENROLL
    postex --> SYS
```

### 2b. How Protocols Flow

Every protocol follows the same pattern. Here's the general flow using Kerberos as an
example — SMB, LDAP, and MSSQL work the same way under the hood:

```mermaid
sequenceDiagram
    participant Caller as Caller (hunter/forge/cli)
    participant Proto as Core Protocol Module
    participant Socket as TCP/UDP Socket
    participant Server as Remote Server (DC/CA)

    Caller->>Proto: request_tgt(user, password)
    Proto->>Proto: Build AS-REQ (ASN.1 DER)
    Proto->>Socket: Connect to kdc:88
    Proto->>Socket: Send raw bytes
    Socket-->>Proto: Receive response bytes
    Proto->>Proto: Parse AS-REP (ASN.1 DER)
    Proto->>Proto: Decrypt enc-part with password hash
    Proto-->>Caller: TgtCredential { ticket, session_key }

    Note over Proto: ~56KB of Kerberos code handles<br/>all message types, encryption types,<br/>and error codes
```

Core owns all the ASN.1 parsing, encryption, and wire format handling. Callers never
touch raw bytes. Every protocol library in core is pure Rust — no shelling out, no
P/Invoke, no C dependencies.

### 2c. Attack Graph Flow

The graph is built from LDAP enumeration data. It uses `petgraph` under the hood with
a custom edge-weight model:

```mermaid
flowchart TD
    LDAP["LDAP Enum Data<br/>Users/Groups/ACLs/Delegations"] --> BUILD["Graph Builder<br/>Node: AD object<br/>Edge: Relationship"]
    BUILD --> STORE["petgraph::DiGraph<br/>NodeMap + EdgeMap"]
    STORE --> PATHFINDER["Dijkstra Pathfinder"]
    PATHFINDER --> QUERY["Query Layer<br/>path_to_da / shortest_path"]

    subgraph EdgeWeights["Edge Weight Model"]
        M0["MemberOf = 0<br/>Free traversal"]
        M1["AdminTo = 1<br/>Direct compromise"]
        M2["HasSession = 2<br/>Cred theft opportunity"]
        M5["HasSpn = 5<br/>Offline cracking needed"]
    end

    BUILD --> EdgeWeights
```

### 2d. Post-Exploitation: EDR & Credential Guard

The post-exploitation layer has three tiers of credential access, tried in order:

```mermaid
flowchart TD
    START["Need credentials from LSASS"] --> TIER1["Tier 1: ALPC<br/>LsaISOHandle via lsadb.dll"]
    TIER1 -->|Success| DONE["Credentials extracted"]
    TIER1 -->|CG blocks ALPC| TIER2["Tier 2: Process Memory<br/>NtOpenProcess + NtReadVirtualMemory<br/>via raw syscalls (asm!)"]
    TIER2 -->|Success| DONE
    TIER2 -->|VBS protects memory| TIER3["Tier 3: WDigest Fallback<br/>Force WDigest registry key<br/>Wait for next logon"]
    TIER3 --> DONE

    subgraph Syscall["Syscall Layer (postex/syscall.rs)"]
        S0["syscall_0 — NtClose"]
        S1["syscall_1 — NtOpenProcess"]
        S2["syscall_2 — NtReadVirtualMemory"]
        S4["syscall_4 — NtProtectVirtualMemory"]
        STUB["DynamicSyscallStub<br/>mov r10, rcx<br/>mov eax, SSN<br/>syscall<br/>ret"]
    end

    TIER2 --> Syscall
    START --> CGDETECT["CG Detection<br/>cg_check.rs<br/>SMB + WMI + LDAP voting"]
    CGDETECT --> TIER1
```

### 2e. ADCS Exploitation (ESC1-16)

The ADCS module covers the entire ESC spectrum. Exploits are broken into individual
files but share a common enrollment pipeline:

```mermaid
flowchart LR
    subgraph Enrollment["Shared Enrollment Pipeline"]
        CSR["Generate CSR<br/>Subject + SAN"]
        WEB["Web Enrollment<br/>HTTP POST to CA"]
        PFX["Parse PKCS#12<br/>Extract cert + key"]
    end

    subgraph Exploits["ESC Exploiters"]
        ESC1["ESC1 — SAN in request"]
        ESC3["ESC3 — Enrollment Agent"]
        ESC6["ESC6 — EDITF flag"]
        ESC8["ESC8 — NTLM Relay"]
        ESC9["ESC9 — UPN Poisoning"]
        ESC10["ESC10 — Weak Mapping"]
        ESC13["ESC13 — OID to Group"]
    end

    Exploits --> CSR
    Exploits --> WEB
    WEB --> PFX
```

ESC4, ESC5, and ESC7 generate LDAP/registry modification commands for the operator
(they require additional privileges to modify template ACLs or CA permissions). ESC8
is special — it doesn't enroll directly, it coordinates with the relay crate to
capture NTLM auth and relay it to the CA web enrollment page.

---

## 3. overthrone-reaper — The Collector

Reaper is the enumeration crate. It talks LDAP to the domain controller, asks nicely
for everything, and returns structured data. No modification — read-only.

### 3a. Enumeration Flow

```mermaid
flowchart TD
    LDAP["LDAP Connection<br/>Server + Credentials"] --> BIND["Bind<br/>Simple / NTLM / Kerberos"]
    BIND --> SEARCH["Base Search<br/>rootDSE → namingContexts"]

    SEARCH --> USERS["Users<br/>sAMAccountName, SPN, UAC, ACL"]
    SEARCH --> GROUPS["Groups<br/>member, adminCount, ACL"]
    SEARCH --> COMPUTERS["Computers<br/>OS, dNSHostName, ACL"]
    SEARCH --> TRUSTS["Trusts<br/>trustPartner, direction, type"]
    SEARCH --> GPOS["GPOs<br/>displayName, gPCFileSysPath"]
    SEARCH --> OUS["OUs<br/>distinguishedName, ACL"]
    SEARCH --> DELEG["Delegations<br/>msDS-AllowedToDelegateTo"]

    USERS --> LAPS["LAPS v1/v2<br/>ms-Mcs-AdmPwd / msLAPS-EncryptedPassword<br/>+ DPAPI Decrypt"]
    USERS --> GPP["GPP Passwords<br/>SYSVOL XML → cpassword → AES decrypt"]
    USERS --> NTLM2TGT["NTLM → TGT<br/>Pass-the-hash pipeline"]

    SEARCH --> ADCSENUM["ADCS Enum<br/>CA server, templates, ACLs"]
    ADCSENUM --> EXPORT["BloodHound Export<br/>JSON users/groups/computers/domains"]
```

### 3b. Snaffler Flow

The Snaffler module crawls SMB shares looking for interesting files:

```mermaid
flowchart LR
    SHARES["Resolve Shares<br/>SMB Enum + config"] --> WALK["Walk Directory Tree<br/>Max depth, max files"]
    WALK --> MATCH["Match Patterns<br/>Extension / Name / Regex / Content hint"]

    MATCH -->|Interest score > 0| CLASSIFY["Classify<br/>Severity: Critical/High/Medium/Low"]
    MATCH -->|Score = 0| SKIP["Skip — safe file"]

    CLASSIFY --> LOG["Log finding<br/>Path, Severity, Reason"]
    LOG --> EXPORT_SNAFF["CSV Export<br/>&lt;stem&gt;_snaffle.csv"]
    LOG --> REPORT["+ finding to EngagementSession"]
```

Under the hood it uses `smbclient` (Linux) or the built-in SMB2 client (cross-platform)
depending on availability. The pattern matching is unit-tested (`file_matches_pattern`
— 23 tests now) but the end-to-end SMB share crawling is not (requires a real file
server).

---

## 4. overthrone-hunter — The Overachiever

Hunter contains the attack primitives. It never modifies AD objects (that's forge's
job) but it requests tickets, cracks hashes, and identifies misconfigurations.

### 4a. Kerberoasting Pipeline

```mermaid
flowchart TD
    SPNS["SPN Accounts<br/>from enum data"] --> FILTER["Filter<br/>skip_asrep_roastable?<br/>aes_only?"]
    FILTER --> TGSREQ["TGS-REQ<br/>Request service ticket"]
    TGSREQ -->|etype 17/18/23| PARSE["Parse TGS-REP<br/>Extract encrypted blob"]
    PARSE --> CRACK["Crack<br/>Embedded wordlist<br/>Rayon parallel<br/>Hashcat fallback"]
    CRACK --> RESULT["CrackedCredential<br/>username:password"]

    FILTER --> ERR["Skip?<br/>Log reason"]
```

Kerberoasting requests come in three flavors: RC4 (etype 23, fast to crack),
AES128 (etype 17), and AES256 (etype 18, slow to crack). The `downgrade_to_rc4`
flag changes what encryption type hunter requests — the KDC will downgrade if the
account supports it.

### 4b. Delegation Chain Automation

Delegation attacks are multi-step. Hunter automates the whole chain:

```mermaid
flowchart TD
    START["Start: User with<br/>GenericAll/Write on<br/>a computer object"] --> CREATE["Step 1: Create<br/>Machine Account<br/>+ msDS-AllowedToActOnBehalfOfOtherIdentity"]
    CREATE --> SID["Step 2: Resolve SID<br/>of new machine account"]
    SID --> RBAC["Step 3: Write RBCD<br/>msDS-AllowedToActOnBehalfOfOtherIdentity<br/>= SID of controlled account"]
    RBAC --> S4U2SELF["Step 4: S4U2Self<br/>Request TGS as DA<br/>TO the controlled machine"]
    S4U2SELF --> S4U2PROXY["Step 5: S4U2Proxy<br/>Use that TGS to request<br/>service ticket to target"]
    S4U2PROXY --> DONE["Step 6: Got service ticket<br/>as DA to target service"]
    DONE --> CLEANUP["Step 7: Auto-cleanup<br/>Remove machine account + RBCD"]

    START --> CHECK["Pre-check<br/>Target OS version<br/>Delegation not disabled"]
```

The whole pipeline is ~628 lines in `delegation_chain.rs`. Every step has error
handling and rolls back cleanly if something fails mid-chain.

---

## 5. overthrone-crawler — The Explorer

Crawler maps trust relationships, analyzes cross-domain attack paths, and now has
network-level OPSEC features for evading detection during reconnaissance.

### 5a. Cross-Domain Trust Mapping

```mermaid
flowchart LR
    subgraph Discovery["Trust Discovery"]
        LDAPTRUST["LDAP: Trusted Domain Object<br/>trustPartner, direction, type"]
        DNS["DNS: SRV _kerberos._tcp.<domain>"]
    end

    Discovery --> TRUSTMAP["Trust Map<br/>+ direction<br/>+ SID filtering status"]

    TRUSTMAP --> ESCALATE["Escalation Analysis<br/>Can we cross?"]
    TRUSTMAP --> FOREIGN["Foreign Enum<br/>Users/groups across trust"]
    TRUSTMAP --> INTERREALM["Inter-Realm TGT<br/>Forge with trust key or PKINIT"]
    FOREIGN --> MSSQLLINKS["MSSQL Link Crawl<br/>xp_cmdshell across trusts"]
```

### 5b. Network OPSEC Features

These are the newer additions that help crawler blend in:

```mermaid
flowchart TD
    START["Crawl starting"] --> PORTROTATE["Source-Port Rotation<br/>PortRotator: atomic round-robin<br/>49152-65535 range"]
    PORTROTATE --> JITTER["OPSEC Pacing<br/>Delay + jitter + concurrency cap"]
    JITTER --> FINGERPRINT["JA3/JA4 Randomization<br/>Randomize cipher order<br/>Randomize group order<br/>Subset ciphers"]
    FINGERPRINT --> OPLOCK["OPLOCK Hijack<br/>SMB create_with_oplock<br/>Wait for break → data"]
    OPLOCK --> RESPOND["Responder Integration<br/>--respond: capture creds<br/>--poison-ip: poison targets"]
    RESPOND --> DONE["Crawl complete"]
```

The port rotator (`PortRotator` in `pacing.rs`) doesn't need admin rights — it uses
ports >= 1024. The JA3/JA4 module is feature-gated behind `tls_fingerprint` because
it pulls in `rustls` as a dependency. The Responder integration is feature-gated
behind `responder` because it depends on the relay crate's poisoner.

---

## 6. overthrone-forge — The Blacksmith

Forge is the persistence crate. It fakes Kerberos tickets, abuses AD CS, and leaves
backdoors. Every function takes a config and returns a result — no side effects,
no println.

### 6a. Ticket Forging Pipeline

Different ticket types need different inputs but share a common PAC construction:

```mermaid
flowchart TD
    subgraph Inputs["What you need"]
        KRBTGT["KRBTGT hash<br/>or PKINIT session key"]
        SVC["Service hash<br/>for silver tickets"]
        PAC["PAC data<br/>KERB_VALIDATION_INFO"]
        TGT["Legitimate TGT<br/>for diamond/sapphire"]
    end

    subgraph Forgers["Forging Functions"]
        GOLDEN["Golden Ticket<br/>forge_golden_ticket()"]
        SILVER["Silver Ticket<br/>forge_silver_ticket()"]
        DIAMOND["Diamond Ticket<br/>forge_diamond_ticket()"]
        SAPPHIRE["Sapphire Ticket<br/>forge_sapphire_ticket()"]
        BRONZEBIT["Bronze Bit<br/>CVE-2020-17049 bypass"]
        INTERREALM["Inter-Realm TGT<br/>forge_interrealm_tgt()"]
    end

    subgraph Outputs["What comes out"]
        KIRBI[".kirbi file"]
        CCACHE[".ccache file"]
        BASE64["Rubeus base64"]
    end

    KRBTGT --> GOLDEN
    SVC --> SILVER
    TGT --> DIAMOND
    TGT --> SAPPHIRE

    GOLDEN --> KIRBI
    GOLDEN --> CCACHE
    SILVER --> KIRBI
    DIAMOND --> KIRBI
    SAPPHIRE --> KIRBI
    INTERREALM --> KIRBI
    BRONZEBIT --> KIRBI

    KIRBI --> CONVERT["convert.rs<br/>kirbi ↔ ccache ↔ base64"]
```

The `Enhanced Diamond` variant parses the legitimate TGT's PAC, locates the KDC
checksum (type 7), and preserves it — the forged ticket carries a checksum that
looks like it was issued by the real KDC. `Sapphire` goes further: it decrypts
the service ticket from S4U2Self, extracts the KDC-issued PAC, and wraps it in
a new TGT encrypted with krbtgt.

### 6b. ADCS Dispatcher Flow

The ADCS dispatcher tries exploits in a priority order (when set to Auto mode):

```mermaid
flowchart TD
    CONFIG["AdcsConfig<br/>CA URL + domain + creds + action"] --> DISPATCH["run_adcs()"]

    DISPATCH -->|Action = Auto| TRY1["Try ESC1<br/>SAN abuse"]
    TRY1 -->|Success| DONE["Return AdcsResult"]
    TRY1 -->|Fail| TRY6["Try ESC6<br/>EDITF flag"]
    TRY6 -->|Success| DONE
    TRY6 -->|Fail| TRY9["Try ESC9<br/>UPN poisoning"]
    TRY9 -->|Success| DONE
    TRY9 -->|Fail| FAIL["None exploitable<br/>Return guidance"]

    DISPATCH -->|Action = Esc1..9| DIRECT["Direct exploit<br/>or command generation"]

    subgraph DirectExploits["Direct Exploits"]
        E1["ESC1: Web Enrollment + SAN"]
        E2["ESC2: Any Purpose EKU"]
        E3["ESC3: Enrollment Agent chain"]
        E6["ESC6: EDITF abuse"]
        E9["ESC9: UPN modify + enroll"]
    end

    subgraph CommandGen["Command Generation"]
        E4["ESC4: LDAP template ACL fix"]
        E5["ESC5: PKI object ACL fix"]
        E7["ESC7: CA permission fix"]
        E8["ESC8: ntlmrelayx command"]
    end

    DIRECT --> DirectExploits
    DIRECT --> CommandGen
```

For ESC4/5/7/8, the dispatcher can't directly exploit (needs additional access or
a relay setup), so it prints the commands the operator should run.

---

## 7. overthrone-pilot — The Strategist

Pilot orchestrates the other crates. It runs the auto-pwn pipeline, manages the
Q-learning engine, and handles session save/resume.

### 7a. Auto-Pwn Stage Machine

Auto-pwn runs through 6 stages, saving state after each one:

```mermaid
flowchart LR
    START["Start"] --> ENUM["Stage 1: Enumerate<br/>Reaper: full LDAP enum<br/>+ policy/delegation/LAPS"]
    ENUM --> GRAPH["Stage 2: Attack Graph<br/>Core: build graph<br/>+ find paths to goal"]
    GRAPH --> ATTACK["Stage 3: Attack<br/>Hunter: roast/spray/coerce<br/>Relay: relay NTLM if needed"]
    ATTACK --> ESCALATE["Stage 4: Escalate<br/>Forge: RBCD/delegation abuse<br/>Hunter: pass-the-hash"]
    ESCALATE --> LATERAL["Stage 5: Lateral<br/>Core: remote exec<br/>+ credential harvesting"]
    LATERAL --> PERSIST["Stage 6: Persist<br/>Forge: golden/silver ticket<br/>+ DCSync + cleanup"]
    PERSIST --> REPORT["Report<br/>Scribe: generate PDF"]

    ENUM -->|Resume from save| GRAPH
    ATTACK -->|Failure| REQ_WIZARD["Wizard mode<br/>Ask operator for input"]
    REQ_WIZARD --> ATTACK
```

Each stage calls into the relevant crate. The executor (`executor.rs`) handles
error recovery: if kerberoasting fails, it tries AS-REP roasting instead. If
all attacks fail at a stage, it pauses and asks for operator input (wizard mode).

### 7b. Q-Learning Flow

The Q-learner improves attack selection over multiple runs:

```mermaid
flowchart TD
    STATE["State Encoding<br/>domain size, policy,<br/>lockout risk, LAPS status,<br/>delegation, creds owned,<br/>admin hosts, stage"]
    STATE --> QTABLE["Q-Table<br/>State → Action → Q-Value"]

    QTABLE --> DECISION["Decision<br/>ε-greedy: explore (30%)<br/>or exploit (best Q)"]
    DECISION --> ACTION["Execute Action<br/>roast / spray / coerce / relay / forge"]

    ACTION --> RESULT["Result<br/>Success + new creds/admin hosts<br/>or Failure + lockouts"]
    RESULT --> REWARD["Reward<br/>+10 new DA cred<br/>+5 new admin host<br/>+2 new user cred<br/>-5 lockout<br/>-3 attack failed"]
    REWARD --> UPDATE["Update Q-Table<br/>Q(s,a) += α[R + γ·max Q(s',a') - Q(s,a)]"]
    UPDATE --> STATE

    DECISION -->|Exploration| RANDOM["Random Action<br/>from available pool"]
    RANDOM --> ACTION
```

The Q-learner is compiled by default (no feature gate). It learns across sessions
if you save the Q-table to disk (`--q-table ./brain.json`).

### 7c. Session Save/Resume

```mermaid
flowchart TD
    SESSION_START["Session starts"] --> SAVE["Save state after each stage<br/>→ JSON file in ~/.overthrone/sessions/"]
    SAVE --> CRASH["Crash / Ctrl+C / VPN drop"]
    CRASH --> RESUME["Resume: --from-session <name><br/>or --resume <path>"]
    RESUME --> LOAD["Load EngagementState<br/>Check what's already populated"]
    LOAD --> SKIP["Skip Enumerate if users/computers/groups present"]
    SKIP --> CONTINUE["Continue from next stage"]
```

The `WizardSession::new_with_state()` constructor enables the skip-Enumerate flow.
It checks whether the loaded state has users, computers, and groups — if so, it
starts at the Attack stage instead of Enumerate.

---

## 8. overthrone-relay — The Interceptor

Relay captures NTLM authentication from one protocol and forwards it to another.
It also handles network poisoning (LLMNR/NBT-NS/mDNS) to trigger authentication.

### 8a. Relay Engine Flow

The core relay path is the same regardless of source/target protocol:

```mermaid
sequenceDiagram
    participant Victim as Victim Machine
    participant Relay as Relay Engine
    participant Target as Target Server

    Victim->>Relay: NTLM NEGOTIATE (Type 1)
    Relay->>Target: Forward NEGOTIATE (Type 1)
    Target-->>Relay: CHALLENGE (Type 2)
    Relay->>Relay: Modify CHALLENGE<br/>Strip SIGN/SEAL flags<br/>(Drop the MIC)
    Relay-->>Victim: Modified CHALLENGE (Type 2)
    Victim-->>Relay: AUTHENTICATE (Type 3)
    Relay->>Relay: Strip MIC from Type 3<br/>(strip_mic_from_type3)
    Relay->>Target: Forward modified AUTHENTICATE (Type 3)

    Note over Relay: Now relay has an authenticated<br/>session to Target using Victim's identity
    Relay->>Target: LDAP add-to-group / SMB file write /<br/>HTTP request replay
```

The engine handles multiple protocol combinations:

```mermaid
flowchart LR
    subgraph Sources["Incoming Auth Sources"]
        SMB_IN["SMB"]
        HTTP_IN["HTTP / WebDAV"]
        TLS_IN["TLS-wrapped"]
    end

    subgraph Engine["Relay Engine"]
        MODIFY["NTLM message modification<br/>MIC strip, flag strip,<br/>DCE/RPC sig strip"]
        RELAY["Forward to target protocol"]
    end

    subgraph Targets["Outgoing Relays"]
        LDAP_OUT["LDAP"]
        SMB_OUT["SMB"]
        EXCHANGE_OUT["Exchange MAPI/EWS"]
        MSSQL_OUT["MSSQL"]
        ADCS_OUT["ADCS (ESC8)"]
    end

    Sources --> Engine
    Engine --> Targets

    subgraph Extras["Extra Features"]
        IPV6["IPv6 transport<br/>Dual-stack listeners"]
        SOCKS5["SOCKS5 proxy<br/>Route via proxy"]
        MTVLS["mTLS mode<br/>VerifyServerCert"]
        COERCE["Auto-coerce<br/>Printer/Petitpotam/DFS"]
        H2S["HTTP→SMB Asymmetric<br/>Capture request → replay"]
    end

    Engine --> Extras
```

### 8b. HTTP→SMB Asymmetric Relay

This is the newer, more sophisticated relay type. It captures the full HTTP request,
extracts the NTLM token, and replays the request as an authenticated NTLM request
to the target:

```mermaid
flowchart TD
    CAPTURE["Victim sends HTTP request<br/>to relay listener"] --> READ["read_full_request()<br/>Content-Length aware body read"]
    READ --> EXTRACT["extract_ntlm_token()<br/>Parse Authorization: NTLM header"]
    EXTRACT --> CLASSIFY["is_http_target()<br/>Is target HTTP/S?"]
    CLASSIFY -->|Yes: HTTP target| REPLAY["replay_authenticated_request()<br/>Replay full HTTP request<br/>with relayed NTLM auth"]
    CLASSIFY -->|No: SMB/LDAP/MSSQL| OK["Return 200 OK<br/>relay succeeded"]
```

### 8c. Poisoning Flow

The poisoner listens for broadcast name resolution queries and answers them:

```mermaid
flowchart TD
    LISTEN["Listen on UDP:137 (NBT-NS)<br/>UDP:5355 (LLMNR)<br/>UDP:5353 (mDNS)"] --> QUERY["Incoming query<br/>'Who is FILESERVER?'"]
    QUERY --> SPOOF["Spoofed response<br/>'FILESERVER is at <attacker_ip>'"]
    SPOOF --> VICTIM["Victim connects to attacker<br/>SMB / HTTP / WPAD"]
    VICTIM --> CAPTURE_START["NTLM auth captured → Relay Engine"]

    QUERY --> FILTER["Filter logic<br/>Don't poison:<br/>- Domain controllers<br/>- Configured exclusions<br/>- Same subnet as querier"]
    FILTER --> SPOOF
```

---

## 9. overthrone-scribe — The Chronicler

Scribe takes an `EngagementSession` (a struct full of findings, credentials, and
timeline data) and turns it into a formatted report.

### 9a. Report Generation Pipeline

```mermaid
flowchart LR
    SESSION["EngagementSession<br/>+ Findings<br/>+ Credentials<br/>+ Timeline<br/>+ Evidence"] --> MAPPER["Mapper<br/>MITRE ATT&CK<br/>technique IDs"]
    SESSION --> NARRATIVE["Narrative<br/>Human-readable<br/>attack story"]

    MAPPER --> RENDERER["Report Renderer"]
    NARRATIVE --> RENDERER

    RENDERER -->|Format = Markdown| MD["markdown.rs<br/>Technical report<br/>+ remediation"]
    RENDERER -->|Format = JSON| JSON["JSON export<br/>Machine-readable"]
    RENDERER -->|Format = PDF| PDF["pdf.rs<br/>printpdf renderer<br/>Executive summary"]

    RENDERER --> EVIDENCE["Evidence hashing<br/>sha256 on each EvidenceItem"]
    RENDERER --> TIMELINE["Timeline view<br/>timeline_by_day()"]
```

All three output formats share the same input data. The markdown report is the most
detailed (full technical breakdown). The PDF is shorter (executive summary with
findings and risk scores). The JSON is for programmatic consumption (SIEMs,
ticketing systems).

---

## 10. overthrone-cli — The Interface

The CLI crate is a binary-only crate (no lib.rs). It parses command-line arguments
with clap and dispatches to the appropriate crate. It also hosts the TUI and the
interactive shell.

### 10a. Command Dispatch

```mermaid
flowchart TD
    MAIN["main.rs<br/>7,241 lines<br/>Clap definitions"] --> DISPATCH["Match subcommand"]

    DISPATCH -->|"ovt auto-pwn"| AUTOPWN["autopwn.rs → pilot::run()"]
    DISPATCH -->|"ovt wizard"| WIZARD["commands/wizard.rs → pilot::wizard()"]
    DISPATCH -->|"ovt enum *"| ENUM["commands/enum_commands/* → reaper"]
    DISPATCH -->|"ovt kerberos *"| KRB["→ hunter"]
    DISPATCH -->|"ovt adcs"| ADCS["→ core::adcs"]
    DISPATCH -->|"ovt forge"| FORGE["→ forge::run_forge()"]
    DISPATCH -->|"ovt graph *"| GRAPH["graph_view.rs / tree_viewer.rs → core::graph"]
    DISPATCH -->|"ovt relay"| RELAY["→ relay"]
    DISPATCH -->|"ovt ntlm *"| NTLM["→ relay::http_asymmetric / relay::relay"]
    DISPATCH -->|"ovt report"| REPORT["→ scribe"]
    DISPATCH -->|"ovt config *"| CONFIG["commands/config.rs → cli_config.rs"]
    DISPATCH -->|"ovt config profile *"| PROFILE["commands/config.rs → profile system"]
    DISPATCH -->|"ovt session *"| SESSION["commands/session.rs → pilot::session"]
    DISPATCH -->|"ovt shell"| SHELL["interactive_shell.rs"]
    DISPATCH -->|"ovt tui"| TUI["tui/runner.rs"]
    DISPATCH -->|"ovt doctor"| DOCTOR["commands/doctor.rs"]

    subgraph SHELLDETAIL["Interactive Shell (3,263 lines)"]
        REPL["rustyline REPL<br/>Tab completion<br/>History<br/>Syntax highlighting"]
        MODULES["Forge modules<br/>golden / silver / diamond / skeleton<br/>use → set → run"]
        REMOTE["Remote shell types<br/>WinRM / SMB / WMI"]
    end

    SHELL --> REPL
    SHELL --> MODULES
    SHELL --> REMOTE

    subgraph CONFIGDETAIL["Config System (1,111 lines)"]
        TOML["TOML loading<br/>XDG-aware paths"]
        PROFILE_SYS["Profile system<br/>Named profiles<br/>OT_CONFIG / OT_PROFILE env"]
        MERGE["Config merge order<br/>CLI flag > env > profile > config > default"]
    end

    CONFIG --> TOML
    CONFIG --> PROFILE_SYS
    CONFIG --> MERGE
```

### 10b. TUI Architecture

The TUI has 6 modules that work together via ratatui:

```mermaid
flowchart TD
    START["ovt tui"] --> RUNNER["runner.rs<br/>Terminal setup (crossterm)<br/>30 FPS render loop"]
    RUNNER --> APP["app.rs<br/>Application state<br/>Tab management"]
    APP --> UI["ui.rs<br/>Layout + widget rendering"]
    APP --> EVENT["event.rs<br/>Keyboard / mouse handling"]

    APP --> GRAPH["graph_view.rs<br/>1,741 lines<br/>Node/edge rendering<br/>Attack graph visualization"]

    GRAPH --> QUIT["q → quit<br/>? → help"]
```

The TUI can run in two modes: live crawler mode (connects to a DC and shows
enumeration progress in real-time) and view-only mode (loads a graph from a JSON
file and lets you explore it).

---

## 11. overthrone-viewer — The Window

The viewer is a standalone web server. It's the only crate that runs as a long-lived
process (the CLI commands exit after they finish). It serves a browser-based graph
GUI.

### 11a. Web Stack

```mermaid
flowchart TD
    USER["Browser<br/>Three.js WebGL"] --> TLS["TLS Terminator<br/>rustls TlsListener"]
    TLS --> AUTH["Auth Middleware<br/>Bearer token or Basic auth<br/>Always-on"]
    AUTH --> CSRF["CSRF Middleware<br/>X-CSRF-Token check on<br/>POST/PUT/DELETE"]
    CSRF --> CORS["CORS<br/>Loopback only<br/>localhost / 127.0.0.1 / ::1"]
    CORS --> RATE["Rate Limiter<br/>Per-user + per-IP<br/>Token bucket"]
    RATE --> ROUTER["Axum Router<br/>Static files + API"]
    ROUTER --> SESSION["Session Store<br/>48-char tokens<br/>8-hour TTL<br/>Multi-user HashMap"]

    subgraph GraphAPI["Graph Endpoints"]
        NODES["/api/nodes<br/>Search + filter"]
        PATHS["/api/paths<br/>Shortest path finder"]
        DETAILS["/api/details<br/>Node + edge detail"]
        STATS["/api/stats<br/>Graph statistics"]
    end

    ROUTER --> GraphAPI

    subgraph Security["Security Features"]
        RANDOM_CREDS["Random credentials on launch<br/>12-char user, 24-char pass<br/>32-char CSRF token"]
        LOOPBACK_BIND["Refuse non-loopback bind<br/>without TLS"]
        TLS_CLIENT["mTLS client cert verification<br/>WebPkiClientVerifier"]
    end

    Security --> TLS
    Security --> AUTH
```

The viewer loads graph data from JSON files (Overthrone exports or BloodHound JSON
collections). It indexes the data and serves it via REST endpoints. The browser
renders the graph using Three.js (migrated from D3.js for GPU-accelerated WebGL
performance). The canvas starts blank — the operator searches for nodes and renders
chunks with configurable budgets (50 to ALL nodes).

---

## 12. Putting It All Together: Full Auto-Pwn

This is what happens when you run `ovt auto-pwn`. The diagram shows every crate
involved and the order of operations:

```mermaid
sequenceDiagram
    participant User
    participant CLI as overthrone-cli
    participant PILOT as overthrone-pilot
    participant REAPER as overthrone-reaper
    participant CORE as overthrone-core
    participant HUNTER as overthrone-hunter
    participant FORGE as overthrone-forge
    participant RELAY as overthrone-relay
    participant SCRIBE as overthrone-scribe

    User->>CLI: ovt auto-pwn -H DC -d CORP -u user -p pass

    CLI->>PILOT: AutoPwnConfig::run()
    Note over PILOT: Stage 1: Enumerate
    PILOT->>REAPER: enum_all(DC, domain, creds)
    REAPER->>CORE: LDAP bind + search
    CORE-->>REAPER: Raw LDAP entries
    REAPER-->>PILOT: ADData { users, groups, trusts, acls, laps, gpp }
    PILOT->>PILOT: Save session state

    Note over PILOT: Stage 2: Attack Graph
    PILOT->>CORE: build_graph(ADData)
    CORE->>CORE: petgraph DiGraph + Dijkstra
    CORE-->>PILOT: AttackGraph + PathsToDA

    Note over PILOT: Stage 3: Attack
    PILOT->>HUNTER: kerberoast(SPN accounts)
    HUNTER->>CORE: TGS-REQ/REP
    CORE-->>HUNTER: Service tickets with hashes
    HUNTER->>HUNTER: Crack hashes (embedded wordlist)
    HUNTER-->>PILOT: CrackedCredentials

    PILOT->>HUNTER: spray(users, common passwords)
    HUNTER->>CORE: Kerberos pre-auth attempts
    CORE-->>HUNTER: Success/failure responses
    HUNTER-->>PILOT: SprayResults

    PILOT->>RELAY: auto_coerce(targets)
    RELAY->>CORE: trigger_printer_bug/petitpotam
    RELAY-->>PILOT: CapturedCredentials

    Note over PILOT: Stage 4: Escalate
    PILOT->>FORGE: RBCD / delegation abuse
    FORGE->>CORE: LDAP modify + S4U2Self/Proxy
    CORE-->>FORGE: Service tickets
    FORGE-->>PILOT: EscalationResult

    Note over PILOT: Stage 5: Lateral
    PILOT->>CORE: exec methods (PsExec/SmbExec/WinRM)
    CORE-->>PILOT: Command output
    PILOT->>CORE: DCSync
    CORE-->>PILOT: All domain hashes

    Note over PILOT: Stage 6: Persist
    PILOT->>FORGE: forge_golden_ticket(krbtgt hash)
    FORGE->>CORE: Ticket crypto
    CORE-->>FORGE: Forged ticket bytes
    FORGE-->>PILOT: GoldenTicket

    Note over PILOT: Generate Report
    PILOT->>SCRIBE: generate_report(EngagementSession)
    SCRIBE-->>PILOT: Report files (md/json/pdf)

    PILOT-->>CLI: EngagementResult
    CLI-->>User: "Domain owned. Report at ./engagement-report.md"
```

---

## 13. Data Flow Summary

Every piece of data in Overthrone flows through a few core types. Here's how they
connect:

```mermaid
flowchart LR
    AD_DATA["ADData<br/>Users / Groups / Computers<br/>ACLs / Trusts / GPOs / LAPS"] --> GRAPH["AttackGraph<br/>petgraph::DiGraph<br/>Node<->Edge map"]
    AD_DATA --> HUNT_RES["HuntResult<br/>Cracked creds<br/>Roastable accounts"]

    HUNT_RES --> CRED_STORE["CredStore<br/>Privilege-ranked<br/>DA > EA > Admin > User"]
    CRED_STORE --> ENG["EngagementSession<br/>All findings + creds + timeline"]
    GRAPH --> ENG

    ENG --> REPORT["ReportOutput<br/>Markdown / JSON / PDF"]
    ENG --> SAVE["Saved to JSON<br/>~/.overthrone/sessions/<domain>-<dc>.json"]

    SAVE --> RESUME_LOAD["Loaded by --from-session<br/>→ EngagementState"]
    RESUME_LOAD --> AD_DATA
```

The `EngagementSession` is the single source of truth for reporting. It's what the
scribe renders, what the pilot saves to disk, and what `--from-session` loads back
into memory. Every crate that discovers something pushes it into the engagement
session.
