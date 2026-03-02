# Overthrone Implementation TODO

## Priority 1: Core CLI Commands (main.rs implementations)
- [x] cmd_shell - Interactive shell command implementation
- [x] cmd_scan - Port scanner CLI integration
- [x] cmd_adcs - ADCS ESC1-ESC8 attack implementations
- [x] cmd_sccm - SCCM abuse command implementation
- [x] cmd_dump - Credential dumping implementation
- [x] cmd_doctor - Environment diagnostics
- [x] cmd_report - Report generation (Markdown, JSON, PDF — all wired)
- [x] cmd_forge - Ticket forging (golden/silver/diamond)
- [x] cmd_crack - Hash cracking
- [x] cmd_rid - RID cycling
- [x] cmd_move - Lateral movement
- [x] cmd_gpp - GPP password decryption
- [x] cmd_laps - LAPS password reading
- [x] cmd_secrets - Secrets dumping
- [x] cmd_c2_deploy - C2 implant deployment (ImplantRequest → deploy_implant)

## Priority 2: Core Module Enhancements
- [x] Enhance shell.rs with real WinRM/SMB/WMI implementations
- [x] Connect scan module to CLI
- [x] Complete ADCS attack implementations (ESC1-ESC8 all implemented)
- [x] Add crypto utilities for GPP/LAPS
- [x] ADCS ESC1 — full Esc1Exploiter with SAN UPN abuse (esc1.rs, 204 lines)
- [x] ADCS ESC6 — full Esc6Exploiter with EDITF_ATTRIBUTESUBJECTALTNAME2 (esc6.rs, 200 lines)
- [x] WinRM Windows output collection — WSManReceiveShellOutput loop
- [x] WASM plugin state persistence — Store cached & reused
- [x] WASM manifest custom section parsing
- [x] WASM smart memory allocation (tries plugin's allocate() first)
- [x] Native plugin free() — uses fn_free when provided
- [x] CLI PDF output wiring — scribe::pdf::render() called from commands_impl.rs
- [x] TUI crawler integration — builds CrawlerConfig, calls run_crawler
- [x] WmiExec DCOM/EPM endpoint mapper
- [x] DSRM pass-the-hash backdoor — connect_with_hash() in dsrm.rs
- [x] Q-Learning adaptive attack engine (optional qlearn feature, 8/8 tests pass)

## Priority 3: Testing & Validation
- [x] Build verification — cargo check --workspace clean
- [x] Clippy checks — zero warnings with -D warnings across entire workspace
- [x] 222 core unit tests passing
- [x] 8 pilot (Q-Learning) tests passing
- [x] 66 crypto tests passing (AES-CTS, ticket, DPAPI, cracker)
- [ ] Integration tests against real lab DC

## Priority 4: Future Enhancements
- [ ] ADCS ESC9-ESC13 variants
- [ ] Additional C2 integrations
- [ ] Performance profiling & optimization
- [ ] Fuzzing for protocol parsers
- [ ] Enhanced reporting templates
- [ ] API documentation (rustdoc)
- [ ] User guide & attack playbook docs
