# Crawler Module

Lateral movement. Why stay on one box when you can be everywhere?

## Purpose

The `overthrone-crawler` crate handles lateral movement techniques: pass-the-hash, pass-the-ticket, trust abuse, and cross-domain compromise.

## Usage

### CLI

```bash
# Remote execution
ovt exec -t 10.10.10.50 -c "whoami /all" -m psexec
ovt exec -t 10.10.10.50 -c "hostname" -m smbexec
ovt exec -t 10.10.10.50 -c "ipconfig" -m winrm
```

### Library

```rust
use overthrone_core::exec::{PsExecConfig, execute as psexec_exec};
use overthrone_core::exec::{SmbExecConfig, execute as smbexec_exec};

// PsExec
let config = PsExecConfig {
    service_name: "OvThr1234".to_string(),
    command: "whoami".to_string(),
    cleanup: true,
    ..Default::default()
};
let result = psexec_exec(&smb_session, &config).await?;

// SMBExec
let result = smbexec_exec(&smb_session, "whoami").await?;
```

## Modules

### escalation

Local privilege escalation paths.

**Discovers:**
- Local admin group memberships
- Service permissions
- Scheduled task permissions
- Unquoted service paths
- DLL hijacking opportunities

### foreign

Foreign group membership analysis.

**What it finds:**
- Users from trusted domains
- Their group memberships
- Cross-domain access paths

**Use case:**
- Find users from other forests with local admin
- Identify cross-domain attack paths

### interrealm

Inter-realm trust exploitation.

**What it handles:**
- TGT translation across trusts
- SID history exploitation
- Cross-forest ticket forging

**Attack scenarios:**
- Child to parent domain escalation
- Cross-forest compromise
- Trust key abuse

### mssql_links

MSSQL linked server exploitation.

**What it finds:**
- Linked servers
- RPC settings
- Impersonation contexts

**Attack path:**
1. Enumerate linked servers
2. Check for `rpc out` enabled
3. Execute commands via `xp_cmdshell` on linked server
4. Chain through multiple links

### pam

PAM (Privileged Access Management) trust exploitation.

**What it handles:**
- PAM trust discovery
- Shadow security principal enumeration
- Just-in-time access abuse

### sid_filter

SID filtering bypass.

**What it finds:**
- Trusts without SID filtering
- SID history exploitation opportunities
- Cross-domain privilege escalation paths

### trust_map

Trust relationship mapping.

**Output:**
- All trust relationships
- Trust direction and type
- Trust attributes and flags

## Remote Execution Methods

### PsExec

Classic service-based execution.

**How it works:**
1. Upload binary to admin share (ADMIN$ or C$)
2. Create service pointing to binary
3. Start service
4. Read output
5. Cleanup service and binary

**Pros:** Reliable, works everywhere
**Cons:** Drops files, creates service

### SMBExec

Service-based without dropping binary.

**How it works:**
1. Create service with `cmd.exe /c` command
2. Redirect output to file on share
3. Start service
4. Read output file
5. Cleanup

**Pros:** No binary upload
**Cons:** More forensic artifacts

### WMIExec

WMI-based remote execution.

**How it works:**
1. Connect to WMI via DCOM
2. Create Win32_Process
3. Execute command
4. Read output

**Pros:** No service creation
**Cons:** Requires WMI, DCOM must be allowed

### WinRM

PowerShell remoting / WS-Man.

**How it works:**
1. Connect to WinRM endpoint (5985/5986)
2. Create shell
3. Execute command
4. Receive output
5. Delete shell

**Pros:** Native, clean
**Cons:** Requires WinRM enabled

## Pass-the-Hash

All methods support NT hash authentication:

```bash
# PtH with PsExec
ovt exec -t 10.10.10.50 -c "whoami" -m psexec \
  --nt-hash aad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Or with environment variable
export OT_NTHASH=8846f7eaee8fb117ad06bdd830b7586c
ovt exec -t 10.10.10.50 -c "whoami"
```

## Detection Considerations

| Method | Artifacts |
|--------|-----------|
| PsExec | Service creation, file drop, Security log 4688, 4624 |
| SMBExec | Service creation, no file drop |
| WMIExec | WMI activity logs |
| WinRM | WinRM logs, 4624 logon events |

## Cross-Platform Support

All methods work on Windows, Linux, and macOS. The SMB implementation uses:
- **Windows:** Native `smb` crate with SSPI
- **Linux/macOS:** `pavao` with libsmbclient