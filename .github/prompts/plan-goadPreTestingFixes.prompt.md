# Plan: GOAD Pre-Testing Fixes

**TL;DR:** Fix 7 concrete issues before GOAD testing. P0s block the core kill chain. P1s reduce reliability. No new features — making existing code production-correct. README cleaned up last.

---

## Phase 1 — SMB2 Packet Signing (P0)

1. Add `sign_required: bool` field to `Smb2Connection` in `crates/overthrone-core/src/proto/smb2.rs`. Set it from the Negotiate response's SecurityMode bit 1 (server requires signing).
2. Add `sign_packet(data: &mut Vec<u8>, session_key: &[u8])` — zeros out signature bytes 48–64, computes HMAC-SHA256 over the full packet, writes result back in.
3. Call `sign_packet()` after finalizing every SMB2 request (`session_setup`, `tree_connect`, `create_file`, `ioctl`, `read_file`, `write_file`, `close_handle`, `query_info`, `set_info`) when `sign_required` is set. The `session_key` field already exists in `Smb2Connection`, so no auth changes needed.

## Phase 2 — Kerberos SPNEGO Auth for Ticket Login (P0)

4. In `smb2.rs`: add `wrap_spnego_kerberos(ap_req: &[u8]) -> Vec<u8>` mirroring `wrap_spnego_init()` but using Kerberos OID (`1.2.840.113554.1.2.2`) instead of NTLMSSP OID in the NegTokenInit.
5. Add `session_setup_kerberos(&self, domain: &str, username: &str, tgd: &TicketGrantingData) -> Result<Vec<u8>>` — builds AP-REQ via existing `build_ap_req()`, wraps in `wrap_spnego_kerberos()`, sends SESSION_SETUP, returns session key.
6. Fix `connect_with_ticket()` in `crates/overthrone-core/src/proto/smb.rs` — non-Windows path currently calls `session_setup_hash(session_key_hex)` (broken). Change to call `conn.session_setup_kerberos(domain, username, &tgd)`.

## Phase 3 — WmiExec Linux Guard (P1)

7. Wrap all WmiExec implementation in `#[cfg(windows)]` in `crates/overthrone-core/src/exec/wmiexec.rs`. Add a `#[cfg(not(windows))]` version of `execute()` returning `Err(OverthroneError::Custom("WmiExec requires Windows — use --method psexec or winrm on Linux"))`.
8. Check `crates/overthrone-core/src/exec/mod.rs` `auto_exec()` — ensure WmiExec is not selected on non-Windows in the auto method pick.

## Phase 4 — Cross-Domain TGT Referral Following (P1)

9. In `crates/overthrone-core/src/proto/kerberos.rs`, inside `request_tgt()`: if KDC returns error code 68 (`KDC_ERR_WRONG_REALM`), extract the suggested realm from the `e-text` or `crealm` field of the KRB-ERROR, resolve its KDC via DNS SRV (`_kerberos._tcp.dc._msdcs.<realm>`), re-issue the AS-REQ to that KDC. Loop max 2 hops to prevent infinite referrals.

## Phase 5 — Clock Skew Check in Doctor (P1)

10. In `crates/overthrone-cli/src/commands/doctor.rs`: add `check_clock_skew(dc_ip: &str)` — bind LDAP anonymously to the DC, query `currentTime` attribute from RootDSE, parse GeneralizedTime, diff against local UTC. Warn if >4 min, fail if >5 min (Kerberos tolerance threshold). Add to the checks list; DC IP taken from existing CLI arg.

## Phase 6 — README Accuracy (P2)

11. Fix "Zero dependencies\*" + footnote on line 57 — replace with honest count.
12. Fix WmiExec rows in the exec matrix (lines ~220, ~370) — add `⚠️ Windows only` where applicable.
13. Add LDAP relay note: signing bypass not implemented, will fail against DCs with LDAP signing enforcement.

---

## Relevant Files

- `crates/overthrone-core/src/proto/smb2.rs` — Steps 1–6 (signing + Kerberos SPNEGO)
- `crates/overthrone-core/src/proto/smb.rs` — Step 6 (`connect_with_ticket` fix)
- `crates/overthrone-core/src/exec/wmiexec.rs` — Step 7
- `crates/overthrone-core/src/exec/mod.rs` — Step 8
- `crates/overthrone-core/src/proto/kerberos.rs` — Step 9
- `crates/overthrone-cli/src/commands/doctor.rs` — Step 10
- `README.md` — Steps 11–13

---

## Verification

1. `cargo clippy --workspace --all-targets -- -D warnings` → zero warnings
2. `cargo fmt --all -- --check` → clean
3. Manual: connect to a DC with SMB signing required — verify no `STATUS_ACCESS_DENIED` on tree_connect
4. Manual: `ovt kerberos get-tgt` + `ovt exec --ticket <kirbi>` from Linux — confirm no NTLM hash fallback
5. `ovt doctor --dc <ip>` — verify clock skew check appears in output

---

## Decisions

- **PSExec output capture:** already implemented (`try_read_output()` exists) — not in scope
- **BloodHound JSON:** already correct (v5 format) — not in scope
- **Cross-domain:** implement 2-hop limit referral loop — no infinite chain risk
- **WmiExec:** keep the Windows implementation intact, only add the non-Windows stub

---

## Further Considerations

1. **SPNEGO NegTokenInit encoding** — `wrap_spnego_kerberos()` needs correct DER/BER encoding for the `MechTypeList` OID. The existing `wrap_spnego_init` likely uses raw bytes — confirm the byte layout before mirroring it, or the GSSAPI negotiation will silently fail. Worth reading smb2.rs `wrap_spnego_init` carefully before Step 4.
2. **Sign on session setup** — SMB2 SESSION_SETUP itself is typically *not* signed (signature field zeroed, flag not set). Signing starts on the next request after session establishment. This ordering must be correct or Windows DCs reject the tree_connect.
3. **DNS SRV for cross-domain** — referral KDC resolution via `trust_info` from the existing in-memory domain map vs. live DNS lookup. The in-memory map (`TrustRelationship`) may already have the referred KDC IP — check before adding a DNS dependency.

make sure these are fully implemented and fully coded with no more gaps, before GOAD testing. The P0s are critical for basic functionality, while the P1s improve reliability and user experience. The README fixes ensure accurate documentation for users.