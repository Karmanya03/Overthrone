# Feature & CLI Status

What actually exists in the binary, what's still cooking, and what was a collective hallucination in the original docs.

> **Last updated:** February 2026

---

## CLI Commands

If it's not in this table, it's not in `main.rs`. If it IS in this table, it works. Pinky promise.

### Working Commands

| Command | Status | Notes |
|---|---|---|
| `ovt exec -t X -c "cmd" -m <method>` | ✅ Works | Remote execution via PsExec/SMBExec/WinRM/AtExec. The real lateral movement command. |
| `ovt smb admin -t X` | ✅ Works | Check admin access on targets |
| `ovt smb shares -t X` | ✅ Works | List shares |
| `ovt smb get` / `ovt smb put` | ✅ Works | File download/upload |
| `ovt smb spider -t X` | ✅ Works | Search shares for interesting files |
| `ovt forge golden` / `silver` / `diamond` | ✅ Works | Ticket forging |
| `ovt graph build` / `path-to-da` / `path` / `stats` / `export` | ✅ Works | Attack graph engine |
| `ovt kerberos roast` / `asrep-roast` | ✅ Works | Kerberoasting & AS-REP roasting |
| `ovt krb get-tgt` / `get-tgs` | ✅ Works | Ticket requests |
| `ovt crack` | ✅ Works | Hash cracking |
| `ovt reaper` (alias: `enum`) | ✅ Works | Full LDAP enumeration |
| `ovt auto` (alias: `auto-pwn`) | ✅ Works | Autonomous attack chain |
| `ovt doctor` | ✅ Works | Environment diagnostics |
| `ovt wizard` | ✅ Works | Interactive guided mode |
| `ovt dump -t X --source sam\|ntds` | ✅ Works | Credential dumping |
| `ovt spray` | ⚠️ Verify | Library works, CLI auth wiring needs verification on some paths |

### Execution Methods (for `ovt exec`)

| Method | Protocol | Details |
|---|---|---|
| `auto` | All | Tries each method until one works (default) |
| `psexec` | DCE/RPC SVCCTL | Service-based execution. Old reliable. |
| `smbexec` | SMB Services | No binary drop. Stealthier. |
| `winrm` | WS-Man + NTLM | PowerShell remoting. Native. Clean. |
| `atexec` | ATSVC | Scheduled tasks. The procrastinator's choice. |
| `wmiexec` | WMI/SCM | SCM fallback works. Full DCOM deferred. |

**Examples:**
```bash
# Basic remote execution
ovt exec -t 10.10.10.50 -c "whoami /all" -m psexec -D corp.local -u admin -p 'Pass'

# Pass-the-Hash
ovt exec -t 10.10.10.50 -c "whoami" -m smbexec --nt-hash aad3b435b51404ee:8846f7eaee8fb117

# Auto method selection — just get me in
ovt exec -t 10.10.10.50 -c "hostname" -D corp.local -u admin -p 'Pass'
```

### Commands That Do NOT Exist

| Command | Reality |
|---|---|
| `ovt move pth` | ❌ Use `ovt exec --nt-hash` instead |
| `ovt move exec` | ❌ Use `ovt exec -m <method>` instead |
| `ovt move ptt` | ❌ Use `ovt exec --ticket` instead |
| `ovt move smb` | ❌ Use `ovt smb` instead |
| `ovt move` (anything) | ❌ The `move` subcommand was never added to the CLI |

The lateral movement *library code* lives in `overthrone-core/src/exec/` and is fully implemented. It's accessed through `ovt exec`, not `ovt move`. Same legs, different name.

---

## Feature Status

### ✅ Full — Works, Tested, Ship It

| Feature | Details |
|---|---|
| **LDAP Enumeration** | Users, groups, computers, trusts, ACLs, GPOs — AD overshares and we listen |
| **Kerberoasting** | TGS requests, hashcat/john output |
| **AS-REP Roasting** | Pre-auth disabled accounts |
| **Attack Graph Engine** | Dijkstra pathfinding, BloodHound-style |
| **Golden Ticket Forging** | KRBTGT forging |
| **Silver Ticket Forging** | Service ticket forging |
| **Diamond Ticket Forging** | TGT PAC modification |
| **PsExec** | DCE/RPC SVCCTL, cross-platform |
| **SMBExec** | Service-based execution, no binary drop |
| **WinRM** | WS-Man + NTLM auth |
| **AtExec** | Scheduled tasks via ATSVC |
| **SMB Operations** | File ops, shares, admin check, PtH |
| **NTLM Auth** | Hash computation, PtH, challenge-response |
| **Registry Hive Parser** | Offline SAM/SYSTEM parsing |
| **WINREG RPC** | Remote registry protocol |
| **Report Generation** | PDF, HTML, JSON |
| **Hash Cracking** | Integrated cracking support |

### ⚠️ Partial — Works-ish, Test in Lab First

| Feature | Status | Reality |
|---|---|---|
| **DCSync** | ⚠️ Partial | Protocol structure exists and talks to DCs. Full replication needs more work. |
| **Shadow Credentials** | ⚠️ Partial | KeyCredential building works. PKINIT auth needs external tools. |
| **Skeleton Key** | ⚠️ Orch Only | Requires LSASS memory patching (Windows-only, needs C2). |
| **Full DCOM/WMI** | ⚠️ Deferred | ~2000 lines of protocol complexity. SCM fallback works. |
| **Autopwn** | ⚠️ Framework | Architecture exists, plans attacks. Full autonomy needs more field testing. |
| **WMIExec** | ⚠️ Partial | SCM fallback works. Full DCOM-based WMI deferred. |
| **Password Spraying** | ⚠️ Verify CLI | Library works. CLI wiring needs verification on some auth paths. |

### ❌ Not Implemented — On the Roadmap

| Feature | Notes |
|---|---|
| **ADCS Abuse (ESC1-ESC8)** | Certificates are the new hashes. Coming soon™. |
| **SCCM/MECM Exploitation** | Microsoft keeps renaming it faster than we can exploit it. |
| **Cross-Forest Trust Abuse** | One forest at a time. |
| **`ovt move` CLI Command** | Never existed. The library has lateral movement. The CLI uses `ovt exec`. |

---

## Housekeeping

| Item | Details |
|---|---|
| `cracked_credentials.txt` | Dev artifact in project root. Should be `.gitignore`'d. |
| `overthrone-cli/` in root | Duplicate/old folder (not in `crates/`). May contain unused files. |
| `target/` | Already in `.gitignore`. Cargo's territory. |
