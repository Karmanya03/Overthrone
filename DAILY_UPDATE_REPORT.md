# What is Overthrone?

Overthrone is a Rust Active Directory exploitation framework. It does
recon, roasting, relay, ticket abuse, ADCS, graphing, cracking, and
reporting from one binary. Basically: the castle siege kit nobody asked
for, but AD absolutely deserved.

## Yesterday

- Confirmed the big WS2025 items are actually in code: BadSuccessor,
  LDAPS fallback for LAPS, Kerberos FAST, LDAPS relay, smart wordlists,
  mitm6, and LDAP paging.
- Cleaned up the audit so it reflects reality instead of optimistic fan
  fiction.

## Till Date

- Solid stuff: LDAP/Kerberos/SMB/ADCS core, roasting, relay, DCSync,
  graphing, cracking helpers, and report generation.
- Still cooking: Azure AD / Entra, proper Credential Guard probing,
  EDR/AMSI/ETW evasion, Exchange relay target support, and a few WS2025
  edge cases.

Short version: the tool is strong, the domain is still the problem.

## 25-05-2026

- **Azure AD / Entra**: Stole more than just enum - Seamless SSO and Golden SAML now actually hit `login.microsoftonline.com` with real HTTP requests instead of leaving sad `log.push()` notes.
- **Credential Guard**: Remote detection via SMB registry works now (queries `LsaCfgFlags` through `\pipe\winreg`). Heuristic fallback still there for when SMB is having a day off.
- **Syscall resolution**: `resolve_syscall_numbers()` actually parses ntdll's PE export table now instead of politely saying "maybe later." EDR hooks, your days are numbered.
- **Exchange relay**: Hunter no longer shrugs and tells you to use the standalone relay - it actually fires one up.
- **Clippy**: 50+ warnings hunted down and clapped. The workspace compiles cleaner than a freshly patched DC.

## 26-05-2026

- **Sapphire Ticket** (`forge/sapphire`): Full chain - requests legitimate TGT, S4U2Self for the target user, decrypts the service ticket with the user's NTLM hash, extracts the real KDC-issued PAC, and forges a new TGT around it with krbtgt encryption. The original KDC checksum is untouched, so KrbtgtFullPacSignature passes. The PAC is genuine KDC stock, not a forgery.
- **Enhanced Diamond** (`forge/diamond`): Upgraded - now parses the legitimate TGT's PAC, locates the KDC checksum (type 7), and preserves it when rebuilding the PAC with elevated privileges. The KDC_ISSUED indicator survives the swap.
- **Bronze Bit** (`forge/bronzebit`): Full CVE-2020-17049 implementation - S4U2Self → S4U2Proxy with PA-PAC-OPTIONS proxy flag, bypassing the "sensitive and cannot be delegated" restriction on constrained delegation targets.
- **Format Conversion** (`convert`): `.kirbi` ↔ `.ccache` ↔ Rubeus-style base64 with auto-format detection. All three directions work via real ASN.1 parsing and binary format encoding.
- **Stealth Upgrades** (`stealth`): Lifetime jitter (±5%), flag randomization (PROXIABLE/MAY_POST_DATE toggling), and PAC noise injection (up-to-dateness padding entry) at configurable stealth levels (None/Basic/Paranoid).
- **Bronze Bit** `s4u2proxy_bronzebit()`: Added to kerberos proto with optional PA-PAC-OPTIONS for explicit proxy request flagging.

## 27-05-2026

- **Graph TUI**: The graph view and tree view now show ACE and DACL context in the right places, including permission details, rollback hints, and clearer edge notes so the important access paths are easier to read.
- **Upload fixes**: Fixed the graph upload flow that was not working correctly before, so loading graph data is now more reliable.
- **Zip support**: Added and cleaned up zip file upload compatibility, so archived graph inputs are handled properly instead of failing early.
- **Node details**: Fixed the node details panels so they open and show the expected information again.
- **Local graph UI**: All the graphs work locally and instantly, no Neo4j, Python, JVm or any setups etc no BS. Everything stays inside the Rust app and starts without extra services.
- **BloodHound comparison**: The experience is lighter and faster to launch than BloodHound, with less setup, fewer moving parts, and clearer operator notes built into the TUI.
- **Result**: Graph review is now simpler to use during daily work, with faster loading, working uploads, and a more direct workflow.