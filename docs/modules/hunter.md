# Hunter Module

Finding the attackable misconfigurations. The "what can we actually exploit" module.

## Purpose

The `overthrone-hunter` crate identifies attackable configurations in Active Directory. Kerberoasting, AS-REP roasting, delegation abuse, and coercion vulnerabilities.

## Usage

### CLI

```bash
# Kerberoast all SPN accounts
ovt krb roast -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'

# Kerberoast specific SPN
ovt krb roast --spn MSSQLSvc/sql01.corp.local -d dc01 -D corp.local -u jsmith -p 'Pass'

# AS-REP roast
ovt krb asrep-roast -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'
```

### Library

```rust
use overthrone_hunter::kerberoast::get_roastable_spns;
use overthrone_hunter::asreproast::get_asrep_roastable;

// Get all Kerberoastable accounts
let roastable = get_roastable_spns(&ldap_session).await?;
for account in &roastable {
    println!("{}: {:?}", account.sam_account_name, account.spns);
}

// Get AS-REP roastable accounts
let asrep = get_asrep_roastable(&ldap_session).await?;
```

## Modules

### kerberoast

Find and roast accounts with SPNs.

**What it does:**
1. Queries LDAP for accounts with `servicePrincipalName` set
2. Requests TGS for each SPN
3. Outputs crackable hash (hashcat mode 13100 / john format)

**Priority targets:**
- Accounts with old passwords (check `pwdLastSet`)
- Service accounts (often have weak passwords)
- SQL service accounts (MSSQLSvc SPNs)

### asreproast

Find accounts that don't require Kerberos pre-authentication.

**What it does:**
1. Queries LDAP for accounts with `DONT_REQ_PREAUTH` flag
2. Requests AS-REP (no pre-auth required)
3. Outputs crackable hash (hashcat mode 18200)

**Why it matters:**
- No valid credentials needed to get hash
- Often finds legacy or misconfigured accounts
- Service accounts sometimes have this flag set by mistake

### constrained

Constrained delegation abuse.

**What it finds:**
- Accounts with `TRUSTED_TO_AUTH_FOR_DELEGATION`
- Target services they can delegate to
- Protocol transition settings

**Attack path:**
1. Compromise account with constrained delegation
2. Request TGT for that account
3. Request TGS for any user to the allowed service
4. Access the service as that user

### unconstrained

Unconstrained delegation discovery.

**What it finds:**
- Accounts/computers with `TRUSTED_FOR_DELEGATION`
- These can impersonate ANY user to ANY service

**High-value targets:**
- Domain Controllers (expected)
- Member servers with unconstrained (suspicious)
- User accounts with unconstrained (very suspicious)

### rbcd

Resource-Based Constrained Delegation abuse.

**What it finds:**
- Computers with `msDS-AllowedToActOnBehalfOfOtherIdentity`
- Accounts with permissions to write this attribute

**Attack path:**
1. Find computer where you can write `msDS-AllowedToActOnBehalfOfOtherIdentity`
2. Create or use a computer account you control
3. Add it to the allowed delegation list
4. Request TGS for any user to that computer
5. Access the computer as that user

### coerce

Coercion attack discovery (PetitPotam, PrinterBug, etc).

**What it finds:**
- Computers with EFSRPC enabled
- Print spooler availability
- Other RPC endpoints for coercion

**Techniques:**
- EFSRPC (PetitPotam)
- Print Spooler (PrinterBug)
- DFSR (DFSCoerce)
- Shadow Copy (ShadowCoerce)

### tickets

Ticket operations and caching.

**Operations:**
- Import/export ccache files
- Parse and display ticket info
- Convert between formats

## Output Formats

### Kerberoast Hash

```
$krb5tgs$23$*user$domain$spn*$hash...
```

Hashcat mode: 13100

### AS-REP Hash

```
$krb5asrep$23$user@domain:$hash...
```

Hashcat mode: 18200

## Cracking

```bash
# Kerberoast
hashcat -m 13100 kerberoast.hashes wordlist.txt

# AS-REP
hashcat -m 18200 asrep.hashes wordlist.txt

# John the Ripper
john --format=krb5tgs kerberoast.hashes --wordlist=wordlist.txt
john --format=krb5asrep asrep.hashes --wordlist=wordlist.txt
```

## Integration

Hunter integrates with:
- **Reaper** - Gets enumeration data to find targets
- **Forge** - Provides tickets for persistence
- **Pilot** - Feeds attack planning with available techniques