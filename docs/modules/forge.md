# Forge Module

Persistence and ticket forging. Take the throne and weld it to your head.

## Purpose

The `overthrone-forge` crate handles persistence mechanisms: Golden Tickets, Silver Tickets, Diamond Tickets, DCSync, Skeleton Keys, and DSRM backdoors.

## Usage

### CLI

```bash
# DCSync - dump all hashes
ovt dump -t dc01.corp.local --source ntds

# The ticket forging is typically done via autopwn or programmatically
```

### Library

```rust
use overthrone_forge::golden::forge_golden_ticket;
use overthrone_forge::silver::forge_silver_ticket;
use overthrone_forge::dcsync::sync_domain;

// Golden Ticket
let ticket = forge_golden_ticket(
    "corp.local",
    "S-1-5-21-...",
    krbtgt_hash,
    "Administrator",
    10 * 365 * 24 * 60 * 60, // 10 years
)?;

// Silver Ticket
let ticket = forge_silver_ticket(
    "corp.local",
    "S-1-5-21-...",
    service_hash,
    "cifs/dc01.corp.local",
    "Administrator",
)?;

// DCSync
let hashes = sync_domain(&session, "dc01.corp.local").await?;
```

## Modules

### golden

Golden Ticket forging.

**What it does:**
- Forge TGT signed with KRBTGT hash
- Valid for any user, any group membership
- Persists until KRBTGT password is reset twice

**Requirements:**
- KRBTGT NT hash
- Domain SID
- Domain name

**Powers:**
- Access any service in the domain
- Be any user including Domain Admin
- Set arbitrary group memberships
- Set arbitrary PAC contents

### silver

Silver Ticket forging.

**What it does:**
- Forge TGS for a specific service
- No DC communication required
- Stealthier than Golden Ticket

**Requirements:**
- Service account NT hash
- Domain SID
- Service SPN

**Use cases:**
- Access specific service without AD logs
- Persist on specific server
- More stealthy lateral movement

### diamond

Diamond Ticket forging.

**What it does:**
- Modify a legitimate TGT
- Change PAC contents
- Less detectable than Golden Ticket

**Requirements:**
- KRBTGT AES key (preferred) or NT hash
- Valid user TGT to modify

### dcsync

DCSync - replicate credentials from DC.

**What it does:**
- Impersonates a Domain Controller
- Requests replication via MS-DRSR
- Dumps all credentials in the domain

**Requirements:**
- Domain Admin or equivalent rights
- Or DCSync permissions on domain object

**Output:**
- All NT hashes
- Kerberos keys (AES, DES)
- Cleartext passwords (reversible encryption)
- Supplemental credentials

### skeleton

Skeleton Key backdoor.

**What it does:**
- Patches LSASS on DC
- Injects a master password
- All accounts accept this password alongside their real one

**Requirements:**
- Domain Admin
- DC access for LSASS patching

**Limitations:**
- Lost on DC reboot
- Requires AD administrator intervention to remove

### dsrm

DSRM backdoor.

**What it does:**
- DSRM is the Directory Services Restore Mode admin
- Local admin on DC
- Set password to known value
- Persist even after domain compromise remediation

**Requirements:**
- Domain Admin
- Access to modify DSRM password

**Stealth:**
- Not visible in AD
- Survives domain recovery scenarios
- Requires local DC access to detect

### acl_backdoor

ACL-based persistence.

**What it does:**
- Grant controlled access rights to compromised account
- Hide in plain sight as legitimate permission

**Examples:**
- `DCSync` rights on domain
- `GenericAll` on Domain Admins group
- `WriteDACL` on key objects

### cleanup

Remove artifacts and traces.

**Operations:**
- Delete created services
- Remove scheduled tasks
- Clean temporary files
- Reset modified permissions

## Detection Considerations

| Technique | Detection |
|-----------|-----------|
| Golden Ticket | KRBTGT password age monitoring |
| Silver Ticket | Service account password rotation |
| DCSync | Monitor for replication from non-DCs |
| Skeleton Key | LSASS memory scanning |
| DSRM | Registry monitoring |
| ACL Backdoor | Regular ACL audits |

## OPSEC Notes

1. **Golden Tickets** are loud if KRBTGT is reset. Consider Diamond Tickets for stealth.
2. **DCSync** creates a replication event. Use during low-activity periods.
3. **Silver Tickets** are stealthiest - no DC communication at all.
4. **ACL Backdoors** blend in if using legitimate-looking group names.