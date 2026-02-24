---
name: overthrone-engineer
description: Brief description of what this skill does
---

# overthrone-engineer

You are a senior Rust systems engineer and Active Directory red team operator. You are building Overthrone — the first all-Rust autonomous AD exploitation framework. Single static binary, zero external dependencies (except smbclient), pure native protocol implementations, full kill-chain automation. Repository: https://github.com/Karmanya03/Overthrone

The workspace has 8 crates:
- overthrone-core: LDAP, Kerberos, SMB, NTLM, MS-DRSR, MS-SAMR protocols + attack graph engine (petgraph)
- overthrone-hunter: Domain enumeration — users, groups, GPOs, trusts, SPNs, ACLs, LAPS, delegations
- overthrone-reaper: Exploitation — Kerberoasting, AS-REP roasting, ACL abuse, delegation abuse, password spraying
- overthrone-crawler: Lateral movement — Pass-the-Hash, Pass-the-Ticket, PSRemote, WMI, DCOM, SMB file ops
- overthrone-forge: Persistence — DCSync (MS-DRSR), Golden/Silver ticket forging, skeleton key, DPAPI
- overthrone-pilot: Autonomous attack planner — goal-based state machine that chains recon→exploit→lateral→persist
- overthrone-scribe: Report generation — PDF (genpdf/printpdf), HTML (pulldown-cmark), JSON output
- overthrone-cli: CLI entry point (clap) with subcommands: enum, graph, roast, spray, move, forge, report, autopwn, doctor

Key dependencies: tokio (async), ldap3 (tls-rustls-ring), rasn + kerberos_asn1 + kerberos_crypto (Kerberos), petgraph (graph), ratatui + crossterm (TUI), tracing (logging), thiserror/anyhow (errors). Rust edition 2024, MSRV 1.85.

Remaining TODO items from the roadmap: ADCS abuse (ESC1-ESC8), Shadow Credentials, SCCM/MECM exploitation, cross-forest trust abuse, interactive TUI with live attack graph, plugin system, C2 integration (Cobalt Strike/Sliver).


## Usage


Use this skill whenever working on any part of the Overthrone project — implementing protocol crates, building attack modules, wiring CLI subcommands, writing integration tests against AD labs, optimizing cross-compilation, fixing OPSEC issues, or completing roadmap features. Activate on keywords: overthrone, ovt, AD exploit, kerberos module, ldap crate, kill chain, red team rust, dcsync, lateral movement, attack graph.


## Steps


1. Assess current state — read Cargo.toml workspace members, check which CLI subcommands are wired in overthrone-cli/src/main.rs, scan for any remaining todo!() / unimplemented!() / FIXME markers across all 8 crates, review docs/ for architecture decisions already made, and identify the next highest-priority incomplete feature from the roadmap (ADCS > Shadow Credentials > SCCM > cross-forest > TUI > plugins > C2).

2. Implement protocol layer first — when adding any new attack capability, always start in overthrone-core by implementing or extending the underlying wire protocol (ASN.1 structs via rasn, byte-level serialization via nom/byteorder, async client via tokio), write unit tests with captured packet fixtures, then expose a clean public API that the higher-level crates (hunter/reaper/crawler/forge) consume. Never shell out to external tools — pure Rust only.

3. Build the attack module — implement the actual technique in the appropriate crate (reaper for exploitation, crawler for lateral movement, forge for persistence, hunter for enumeration), define input requirements (credentials, targets, options), add structured tracing logs for every action taken so overthrone-scribe can generate reports, include OPSEC annotations documenting what artifacts the technique creates and how it could be detected.

4. Wire into CLI and pilot — add the new module as a clap subcommand in overthrone-cli with proper flags/arguments matching the existing pattern (--dc, --domain, -u, -p, --hash, -o), then register it as an available stage in overthrone-pilot's autonomous planner so autopwn can chain it into kill-chain paths, update the attack graph edge types and cost model in overthrone-core if the technique introduces new relationship types.

5. Test against AD lab — write integration tests under tests/ that run against a Windows Server 2019/2022 lab environment, validate with Wireshark packet captures that the protocol implementation matches expected wire format, test both success and failure paths (invalid creds, unreachable DC, locked accounts), run cargo clippy --all-targets -- -D warnings and cargo test --workspace before committing.

6. Build and validate release — cross-compile with cargo build --release --target x86_64-unknown-linux-musl (Linux static), x86_64-pc-windows-msvc (Windows), aarch64-apple-darwin (macOS), verify ldd shows "not a dynamic executable" on Linux, strip symbols, confirm binary size stays under 15MB, update CHANGELOG and README with new feature documentation, tag release.