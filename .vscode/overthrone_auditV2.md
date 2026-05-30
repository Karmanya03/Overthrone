# Pentest Toolkit Audit - v2

# Overthrone Gap Analysis

Comparing v0.2.1-beta against production-grade AD tooling.
Updated May 2026.

Overthrone is a Rust Active Directory exploitation framework: LDAP,
Kerberos, SMB, relay, ADCS, graphing, cracking, and reporting in one
binary. The short version is simple: one tool, many ways to make AD
administrators sigh deeply.

## Current Verdict

Production readiness is now closer to the mid-60s than the low-50s,
because several previously speculative items are now real code instead of
slides:

- BadSuccessor / dMSA abuse is implemented.
- LDAPS fallback for WS2025 confidential LDAP reads is implemented.
- Kerberos FAST armoring support exists.
- NTLM relay over LDAP/LDAPS exists.
- LDAP paging exists on the normal ldap3 path.
- Smart wordlist generation exists.
- mitm6 / IPv6 poisoning exists.
- WS2025-aware strong-mapping and LAPS handling exist.

The remaining risk is no longer "does it run". It is "which modern AD
controls still break the old playbook, and which gaps are still just not
there yet?" The biggest unfinished areas are Azure AD / Entra coverage,
real EDR/AMSI/ETW evasion, a definitive remote Credential Guard probe,
and Exchange-specific relay target support.

## What Has Actually Progressed

- LDAP enumeration is solid, and bulk searches now use paging on the
  standard LDAP path.
- Kerberoasting, AS-REP roasting, password spray, and ticket format
  conversion are implemented and usable.
- DCSync, ADCS ESC1/ESC6, and the broader ADCS flow remain present.
- BadSuccessor is now a real WS2025-specific attack path instead of a
  note in the margins.
- LAPS reads can fall back to LDAPS when WS2025 confidential attributes
  refuse plaintext LDAP.
- FAST support is present for hardened Kerberos environments.
- Smart wordlists are generated from LDAP data instead of relying only
  on the bundled 10K list.
- mitm6 / IPv6 relay-style positioning is now in the codebase.

## Still Partial Or Missing

- Credential Guard detection exists, but it is still heuristic and not a
  full remote pre-flight probe.
- SMB relay remains fragile in fully signed networks.
- Azure AD / Entra is still mostly scaffold, not full operational
  coverage.
- EDR, AMSI, and ETW evasion are still absent.
- Exchange-specific relay target support is still missing.
- Some WS2025 edge cases still need lab validation, especially FAST,
  strong mapping, and mixed signed / unsigned relay paths.

## WS2025 Reality Check

| Area | Current State | Overthrone Status |
|---|---|---|
| LDAP signing required | Plain LDAP relay to DCs breaks | LDAPS path exists, plain LDAP DC relay is still blocked |
| SMB signing required outbound | Classic SMB relay gets worse | SMB2 client handles signing, relay needs target awareness |
| Credential Guard default-on | LSASS-touching paths lose value | Partial detection only |
| NTLMv1 removed | Legacy relay logic is dead weight | Should be treated as NTLMv2-only |
| SMB auth delay | Bruteforce over SMB slows down hard | Kerberos spray stays the better route |
| Confidential LDAP attrs | Plaintext reads can lie by omission | LDAPS fallback exists |
| dMSA / BadSuccessor | New WS2025 attack surface | Implemented |
| FAST armoring | Hardened KDCs may require it | Support exists, more validation needed |

## Remaining Gaps That Still Matter

- Azure AD / Entra ID hybrid attack surface.
- Proper remote Credential Guard detection.
- EDR/AMSI/ETW evasion for monitored environments.
- Exchange relay target support.
- Broader CVE coverage beyond the core WS2025 attack paths.
- Better validation of the WS2025-specific relay and mapping edge cases.

## Bottom Line

Overthrone is no longer missing the big WS2025-specific pieces that the
old audit treated as hypothetical. The code now has real coverage for
BadSuccessor, LDAPS fallback, FAST, relay over LDAPS, smart wordlists,
mitm6, and paging. What still keeps it from feeling complete is the
usual enterprise reality tax: Azure AD, evasions, and the long tail of
post-2025 edge cases.
