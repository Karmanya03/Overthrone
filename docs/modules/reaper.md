# Reaper Module

LDAP enumeration on overdrive. BloodHound's data collector without the .NET dependency.

## Purpose

The `overthrone-reaper` crate handles full domain enumeration via LDAP. It discovers users, groups, computers, trusts, GPOs, OUs, ACLs, delegations, LAPS, MSSQL links, and ADCS configurations.

## Usage

### CLI

```bash
# Full enumeration
ovt reaper -d dc01.corp.local -D corp.local -u jsmith -p 'Password1'

# Specific modules only
ovt reaper -d dc01 -D corp.local -u jsmith -p 'Pass' -m users,groups,computers

# With ACL enumeration (slower, but finds the good stuff)
ovt reaper -d dc01 -D corp.local -u jsmith -p 'Pass' -m acls

# Output to file
ovt reaper -d dc01 -D corp.local -u jsmith -p 'Pass' -o enum.json
```

### Library

```rust
use overthrone_reaper::runner::{ReaperConfig, run_reaper};

let config = ReaperConfig {
    dc_ip: "10.10.10.1".to_string(),
    domain: "corp.local".to_string(),
    base_dn: "DC=corp,DC=local".to_string(),
    username: "jsmith".to_string(),
    password: Some("Password1".to_string()),
    nt_hash: None,
    modules: vec!["users".to_string(), "groups".to_string()],
    page_size: 500,
};

let result = run_reaper(&config).await?;
println!("Found {} users", result.users.len());
```

## Modules

### users

Enumerates all user accounts.

**Collected:**
- samAccountName
- displayName
- email
- enabled/disabled status
- locked status
- password last set
- last logon
- group memberships
- SPNs
- pre-auth requirements
- delegation settings

### groups

Enumerates all groups.

**Collected:**
- name
- description
- members
- nested memberships
- group type (security/distribution)
- scope (domain local/global/universal)

### computers

Enumerates all computer accounts.

**Collected:**
- name
- DNS hostname
- operating system
- enabled status
- last logon
- SPNs
- delegation settings
- LAPS status

### trusts

Enumerates domain and forest trusts.

**Collected:**
- trust partner
- trust direction
- trust type
- trust attributes
- SID filtering status

### spns

Enumerates accounts with Service Principal Names.

**Collected:**
- account name
- SPN list
- password last set (for kerberoasting priority)

### acls

Enumerates Access Control Lists. This is the slow but valuable one.

**Collected:**
- object DN
- ACEs (Access Control Entries)
- trustee
- access mask
- inheritance

**Finds:**
- GenericAll permissions
- WriteDACL permissions
- WriteOwner permissions
- ForceChangePassword permissions
- DCSync capabilities

### gpos

Enumerates Group Policy Objects.

**Collected:**
- name
- GUID
- links (OUs, sites)
- status (enabled/disabled)

### ous

Enumerates Organizational Units.

**Collected:**
- name
- DN
- linked GPOs
- child objects

### delegations

Enumerates delegation configurations.

**Collected:**
- unconstrained delegation accounts
- constrained delegation accounts
- resource-based constrained delegation
- protocol transitions

### laps

Enumerates LAPS (Local Admin Password Solution) configurations.

**Collected:**
- computers with LAPS
- LAPS password readable by
- password expiration

### mssql

Enumerates MSSQL linked servers.

**Collected:**
- SQL servers
- linked server configurations
- RPC settings

### adcs

Enumerates Active Directory Certificate Services.

**Collected:**
- CAs
- templates
- enrollment permissions
- ESC vulnerability indicators

## Output Structure

```rust
pub struct ReaperResult {
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>,
    pub computers: Vec<ComputerInfo>,
    pub trusts: Vec<TrustInfo>,
    pub spn_accounts: Vec<SpnAccount>,
    pub acls: Vec<AclInfo>,
    pub gpos: Vec<GpoInfo>,
    pub ous: Vec<OuInfo>,
    pub delegations: Vec<DelegationInfo>,
    pub laps: Vec<LapsInfo>,
    pub mssql_links: Vec<MssqlLinkInfo>,
    pub adcs: Vec<AdcsInfo>,
}
```

## Performance Notes

- Uses paged LDAP queries (default 500 entries per page)
- Concurrent module execution where possible
- ACL enumeration is the slowest module (every object, every ACE)
- For large domains, consider running modules separately

## Integration with Attack Graph

Reaper output feeds directly into the attack graph builder:

```rust
let enum_data = run_reaper(&config).await?;
let mut graph = AttackGraph::new();
graph.ingest_enumeration(&enum_data);
```

The graph builder creates nodes for each object and edges for each relationship discovered during enumeration.