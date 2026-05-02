# Architecture Overview

Overthrone is a Rust workspace with 8 crates organized around the AD attack lifecycle. Each crate handles one phase of making sysadmins regret their GPO configurations.

## Crate Structure

```
overthrone/
├── crates/
│   ├── overthrone-core       # Protocols, crypto, graph engine
│   ├── overthrone-reaper     # LDAP enumeration
│   ├── overthrone-hunter     # Attack hunting (roasting, etc)
│   ├── overthrone-crawler    # Lateral movement
│   ├── overthrone-forge      # Persistence (tickets, DCSync)
│   ├── overthrone-pilot      # Autonomous planning
│   ├── overthrone-scribe     # Reporting
│   └── overthrone-cli        # CLI binary
```

## Crate Responsibilities

### overthrone-core

The foundation. Everything else builds on this.

**Modules:**
- `proto/` - Protocol implementations (LDAP, Kerberos, SMB, NTLM, DNS, DRSR)
- `crypto/` - Cryptographic primitives (AES-CTS, HMAC-MD5, MD4, RC4, ticket forging)
- `graph/` - Attack graph engine (builder, pathfinder, nodes/edges)
- `exec/` - Remote execution (PsExec, SMBExec, WMIExec, WinRM)
- `config.rs` - Configuration management
- `error.rs` - Error types
- `types.rs` - Common types

**Key Types:**
```rust
pub struct LdapSession { ... }
pub struct SmbSession { ... }
pub struct KerberosClient { ... }
pub struct AttackGraph { ... }
pub struct Pathfinder { ... }
```

### overthrone-reaper

Domain enumeration via LDAP. BloodHound's data collector without the .NET.

**Modules:**
- `users.rs` - User enumeration
- `computers.rs` - Computer enumeration
- `groups.rs` - Group enumeration
- `trusts.rs` - Domain trust discovery
- `spns.rs` - SPN scanning
- `acls.rs` - ACL enumeration
- `gpos.rs` - GPO discovery
- `ous.rs` - OU enumeration
- `delegations.rs` - Delegation discovery
- `laps.rs` - LAPS enumeration
- `mssql.rs` - MSSQL linked servers
- `adcs.rs` - ADCS enumeration
- `runner.rs` - Orchestration

**Output:** `ReaperResult` containing all enumerated objects.

### overthrone-hunter

Finding attackable misconfigurations.

**Modules:**
- `kerberoast.rs` - Kerberoastable account discovery
- `asreproast.rs` - AS-REP roastable discovery
- `constrained.rs` - Constrained delegation abuse
- `unconstrained.rs` - Unconstrained delegation discovery
- `rbcd.rs` - RBCD abuse
- `coerce.rs` - Coercion attacks (PetitPotam, etc)
- `tickets.rs` - Ticket operations
- `runner.rs` - Orchestration

### overthrone-crawler

Lateral movement. The "why stay on one box when you can be everywhere" crate.

**Modules:**
- `escalation.rs` - Local privilege escalation
- `foreign.rs` - Foreign group membership
- `interrealm.rs` - Inter-realm trust abuse
- `mssql_links.rs` - MSSQL lateral movement
- `pam.rs` - PAM trust abuse
- `sid_filter.rs` - SID filtering bypass
- `trust_map.rs` - Trust mapping
- `runner.rs` - Orchestration

### overthrone-forge

Persistence. Taking the throne and welding it to your head.

**Modules:**
- `golden.rs` - Golden ticket forging
- `silver.rs` - Silver ticket forging
- `diamond.rs` - Diamond ticket forging
- `dcsync.rs` - DCSync user creation
- `skeleton.rs` - Skeleton key
- `dsrm.rs` - DSRM backdoor
- `acl_backdoor.rs` - ACL-based persistence
- `cleanup.rs` - Cleanup operations
- `validate.rs` - Validation
- `runner.rs` - Orchestration

### overthrone-pilot

The autopilot. Plans and executes attack chains.

**Modules:**
- `planner.rs` - Attack path planning
- `executor.rs` - Step execution
- `goals.rs` - Goal definitions and state management
- `playbook.rs` - Attack playbooks
- `adaptive.rs` - Adaptive planning
- `wizard.rs` - Interactive wizard
- `runner.rs` - Orchestration

**Key Types:**
```rust
pub struct Planner { ... }
pub struct EngagementState { ... }
pub enum AttackGoal { ... }
pub struct PlanStep { ... }
```

### overthrone-scribe

Reporting. The difference between pentesting and crimes.

**Modules:**
- `mapper.rs` - Data mapping
- `markdown.rs` - Markdown generation
- `narrative.rs` - Narrative generation
- `mitigations.rs` - Mitigation recommendations
- `pdf.rs` - PDF generation
- `session.rs` - Session management
- `runner.rs` - Orchestration

### overthrone-cli

The command-line interface. Pretty colors included.

**Structure:**
- `main.rs` - Entry point, command routing
- `auth.rs` - Credential handling
- `autopwn.rs` - Autopwn command
- `banner.rs` - ASCII art banners
- `commands/` - Subcommand modules
  - `wizard.rs` - Interactive wizard
  - `doctor.rs` - Environment diagnostics

## Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   LDAP      │────▶│   REAPER    │────▶│    GRAPH    │
│   (389)     │     │             │     │   BUILDER   │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   TARGET    │◀────│   PILOT     │◀────│  PATHFINDER │
│   (DC/Host) │     │  (Planner)  │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │
       │                   ▼
       │           ┌─────────────┐
       │           │  EXECUTOR   │
       │           │ (Execution) │
       │           └─────────────┘
       │                   │
       ▼                   ▼
┌─────────────┐     ┌─────────────┐
│    SMB/     │     │   FORGE     │
│   WinRM     │────▶│ (Persist)   │
└─────────────┘     └─────────────┘
                            │
                            ▼
                    ┌─────────────┐
                    │   SCRIBE    │
                    │  (Report)   │
                    └─────────────┘
```

## Protocol Stack

| Protocol | Crate | Use |
|----------|-------|-----|
| LDAP/LDAPS | core | Domain enumeration |
| Kerberos | core | Authentication, ticket ops |
| SMB 2/3 | core | File ops, named pipes |
| NTLM | core | Auth, pass-the-hash |
| MS-DRSR | core | DCSync replication |
| WS-Man | core | WinRM (non-Windows) |
| DNS | core | Domain discovery |

All protocols are pure Rust. No Python, no .NET, no native library shims (except libsmbclient on Linux/macOS for SMB).

## Cross-Platform Architecture

### Windows

```
SMB ──────▶ smb crate (SSPI/Win32)
WinRM ────▶ Win32 WS-Man API
NTLM ─────▶ SSPI
Kerberos ─▶ SSPI
```

### Linux/macOS

```
SMB ──────▶ pavao (libsmbclient)
WinRM ────▶ Native WS-Man + ntlmclient
NTLM ─────▶ ntlmclient
Kerberos ─▶ Pure Rust implementation
```

The `cfg` gates in `overthrone-core/src/proto/smb.rs` and `overthrone-core/src/exec/winrm/` handle platform differences.

## Attack Graph Engine

The graph engine is a weighted directed graph with Dijkstra pathfinding.

**Node Types:**
- User
- Computer
- Group
- Domain
- OU
- GPO

**Edge Types (with costs):**
- `MemberOf` (0)
- `AdminTo` (1)
- `GenericAll` (1)
- `HasSession` (2)
- `HasSpn` (5)
- `TrustedBy` (4)
- ... and more

**Pathfinding:**
```rust
let path = graph.shortest_path("jsmith", "Domain Admins")?;
// Returns AttackPath with total_cost, hop_count, and hops
```

## Error Handling

All errors flow through `overthrone-core/src/error.rs`:

```rust
pub enum OverthroneError {
    Ldap(String),
    Kerberos(String),
    Smb(String),
    Exec(String),
    Graph(String),
    Config(String),
    // ...
}
```

Results are propagated with `anyhow` for ergonomic error handling.

## Configuration

Configuration is layered:

1. Built-in defaults
2. `configs/default.toml`
3. Environment variables (`OT_*`)
4. CLI flags

Configuration type in `overthrone-core/src/config.rs`.

## Testing

Integration tests in `tests/integration/` cover:
- Crawler trust mapping
- Forge ticket generation
- Hunter roasting
- Pilot planning
- Reaper enumeration
- Scribe reporting

Unit tests are inline in modules.

## Adding New Modules

1. Create module in appropriate crate
2. Implement `runner.rs` orchestration
3. Add CLI command in `overthrone-cli`
4. Update documentation
5. Add integration test

## Dependencies Highlights

| Crate | Purpose |
|-------|---------|
| `ldap3` | LDAP client |
| `kerberos_asn1` | Kerberos ASN.1 types |
| `kerberos_crypto` | Kerberos crypto |
| `rasn` | ASN.1 codec |
| `petgraph` | Graph data structure |
| `tokio` | Async runtime |
| `clap` | CLI parsing |
| `colored` | Terminal colors |
| `tracing` | Logging |

Platform-specific:
| Crate | Platform | Purpose |
|-------|----------|---------|
| `smb` | Windows | SMB client |
| `windows` | Windows | Win32 APIs |
| `pavao` | non-Windows | libsmbclient bindings |
| `ntlmclient` | non-Windows | NTLM auth |
| `quick-xml` | non-Windows | WS-Man XML |

## Performance Considerations

- Async I/O throughout (tokio)
- Concurrent LDAP queries
- Connection pooling for SMB
- Streaming for large file transfers
- Incremental graph updates

## Security Considerations

- No credentials in logs (tracing filters)
- Memory zeroing for sensitive data
- No shell escaping (native protocol implementations)
- Cleartext password handling minimized