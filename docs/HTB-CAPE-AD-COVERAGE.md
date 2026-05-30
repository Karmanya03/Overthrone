# HTB CAPE / AD Coverage Map

This file maps the public HTB Academy/CAPE topic surface to Overthrone commands and planner actions. It is not a copy of HTB paid course content; it is a public-source coverage checklist for keeping OVT's enterprise AD workflow honest.

Sources checked on 2026-05-12:

- HTB CAPE blog: https://www.hackthebox.com/blog/htb-cape-exam-explained-pentest-job-role-path-certification
- HTB Academy Active Directory Enumeration path: https://academy.hackthebox.com/path/preview/active-directory-enumeration
- HTB Academy Active Directory Enumeration & Attacks: https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks/introduction-to-active-directory-enumeration--attacks
- HTB Academy Active Directory PowerView: https://academy.hackthebox.com/course/preview/active-directory-powerview/powerviewsharpview-overview--usage
- HTB Academy Active Directory BloodHound: https://academy.hackthebox.com/course/preview/active-directory-bloodhound
- HTB Academy DACL Attacks I: https://academy.hackthebox.com/course/preview/dacl-attacks-i
- HTB Academy ADCS Attacks: https://academy.hackthebox.com/course/preview/adcs-attacks
- HTB Academy MSSQL, Exchange, and SCCM Attacks: https://academy.hackthebox.com/course/preview/mssql-exchange-and-sccm-attacks

## Coverage

| HTB/CAPE public topic | OVT command surface | QLearner/planner action |
|---|---|---|
| Deep LDAP enumeration | `ovt enum users/computers/groups/trusts/gpos/policy/all`, `ovt powerview ...` | `EnumerateUsers`, `EnumerateComputers`, `EnumerateGroups`, `EnumerateTrusts`, `EnumerateGpos`, `EnumeratePasswordPolicy` |
| BloodHound-style attack path analysis | `ovt graph gui`, `ovt graph path`, `ovt graph export --bloodhound` | graph-aware planning via collected state and trail hints |
| PowerView/SharpView style object enumeration | `ovt powerview users/computers/groups/trusts/spns/asrep/delegations/gpos/policy/laps/acls/all` | same recon actions, plus command hints in the trail |
| Password spraying and password policy | `ovt enum policy`, `ovt spray`, `ovt powerview policy` | `EnumeratePasswordPolicy`, `PasswordSpray` |
| Kerberoasting / AS-REP roasting | `ovt enum spns`, `ovt enum asrep`, `ovt kerberos roast`, `ovt kerberos asrep-roast`, `ovt crack` | `Kerberoast`, `AsRepRoast`, `CrackHashes` |
| SMB null/session/share discovery and sensitive files | `ovt scan --smb`, `ovt smb shares`, `ovt snaffler`, `ovt gpp` | `EnumerateShares` |
| LAPS/gMSA read paths | `ovt enum laps`, `ovt laps`, graph ACE guidance for `ReadLapsPassword`/`ReadGmsaPassword` | `EnumerateLaps` |
| DACL/ACE abuse | `ovt acl enum`, `ovt acl force-password`, `ovt acl add-member`, `ovt acl write-dacl`, `ovt acl write-spn`, `ovt guid ...` | graph and trail guidance for GenericAll, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, WriteSelf/AddSelf, CreateChild, shadow credentials, SPN writes, delegation writes, GPO link writes, and password-policy writes |
| NTLM relay/coercion | `ovt ntlm capture`, `ovt ntlm relay`, `ovt ntlm smb-relay`, `ovt ntlm http-relay` | `Coerce` and relay-aware fallback decisions |
| Delegation and RBCD | `ovt enum delegations`, `ovt powerview delegations`, `ovt move escalation` | `ConstrainedDelegation`, `UnconstrainedDelegation`, `RbcdAttack` |
| ADCS misconfiguration chains | `ovt adcs enum`, `ovt adcs esc1` through `ovt adcs esc13`, `ovt adcs request` | `AdcsEnumerate`, `AdcsEsc1` through `AdcsEsc13` as separate Q-learning action families |
| MSSQL / linked servers | `ovt mssql query`, `ovt mssql linked-servers`, `ovt mssql check-xp-cmd-shell`, `ovt mssql xp-cmd-shell` | command hints and escalation/lateral-movement planning |
| SCCM/MECM | `ovt sccm enum`, `ovt sccm abuse`, `ovt sccm deploy` | command hints for enterprise lateral movement expansion |
| Post-exploitation and reporting | `ovt dump`, `ovt secrets`, `ovt report`, `ovt graph export`, trail files under `loot/trails/` | `DumpSam`, `DumpLsa`, `DumpNtds`, `DumpDcc2`, `DcsSync`, final state summary |

## Release Notes For 0.1.46

- GUI graph rendering now follows a blank-first, search/chunk-driven BloodHound-style flow with deterministic left-to-right hierarchy rather than a circular force cluster.
- The graph detail rail remains visible while the control sidebar is collapsed.
- TUI and GUI ACE guidance now include extended rights, shadow credentials, SPN/delegation writes, ADCS enrollment and mapping, GPO link writes, LAPS/gMSA reads, and password-policy writes.
- `ovt snaffler`, `ovt powerview`, and `ovt guid` are real CLI commands, and the command reference examples use recognized flags.
- QLearner tracks ESC1-ESC13 as distinct action families and writes OVT command hints plus phase-wise important findings into one per-run trail file named with domain and Domain IP.
