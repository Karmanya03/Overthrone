# AGENTS Session History

## Build Command
```powershell
cargo build
```

## Completed Tasks
- **MS-SCMR RPC**: `scmr_exec` in `smb_exec.rs`, `MS_SCMR_UUID` re-exported from `epm.rs`. `WmiExec` runner uses it as fallback.
- **Cert Abuse**: `RequestClient`, `ICertPassage`, `RemoteCertService`, ESC1/3/8/11/12 handlers in `overthrone-forge`.
- **LDAPS Relay**: TLS wrapping in `relay.rs`, `RelayStream` / `RelayIo` trait, `build_relay_tls_config()`, CLI `--ldaps` flag.
- **LDAP Pagination**: `ldap3` backend handles pagination; native NTLM/LDAP single-object lookups don't need it.
- **Coercion Trigger**: Functions in `core/src/proto/coerce.rs` (`trigger_printer_bug`, `trigger_petitpotam`, `trigger_dfs_coerce`). TCP-coercion wrapper in `pilot/src/coerce_tcp.rs` (wired into `lib.rs`).
- **FAST Armoring**: `ArmoredTgsReq`, `PA_PAC_OPTIONS`, `KERB_AD_RESTRICTION_ENC` handling in `kerberos.rs`.
- **AES-Only Kerberoasting**: `kerberoast_ex()` / `request_service_ticket_ex()` with `aes_only` param. CLI `roast --opsec` flag. Hunter `KerberoastConfig::downgrade_to_rc4`.
- **Resource-Based Constrained Delegation**: `rBCD` module with `configure_rbcd()`, `verify_rbcd()`, `clear_rbcd()`.
- **DCSync**: `drsuapi.rs` with `DsGetNCChanges` handler, `Drsr` replication via RPC, `cmd_dcsync()` in CLI.
- **Hashcat GPU Subprocess**: `hashcat_gpu.rs` with `HashcatGpuConfig`, `run_hashcat_gpu()`, `which_hashcat()`. CLI `crack --hashcat` flag. `CrackerConfig::prefer_hashcat`.
- **ESC9/10 WS2025 Fix**: `CertAutoEnroll` ICertPassage enrollment for ESC9/10 patterns, `EnrolmentWebServiceClient`.
- **Code Quality**: Fixed all clippy warnings, formatting, orphaned code, stale cfg gating, and two failing tests to achieve Rank S across all crates.
- **coerce_tcp wired**: TCP coercion wrapper in `pilot/src/coerce_tcp.rs` now exported from pilot `lib.rs`.
- **EPM TCP resolution**: `resolve_uuid_via_epm_tcp()` in `core/src/proto/epm.rs` resolves RPC UUIDs to TCP endpoints.
- **AdaptiveEngine S-rank**: `max_retries` wired as global fallback instead of dead code.
- **Audit correction**: `technical_debt_and_flaws.md` corrected — coercion code IS real (misnamed in earlier docs, not fabricated).

## File Layout
```
crates/
  overthrone-core/src/
    proto/
      kerberos.rs       — kerberoast_ex, request_service_ticket_ex, FAST armoring
      epm.rs            — MS-SCMR re-export, build_rpc_bind/request (pub)
      drsuapi.rs        — DCSync (DsGetNCChanges)
    exec/
      smb_exec.rs       — WmiExec runner with MS-SCMR as fallback
    crypto/
      cracker.rs        — HashCracker, CrackerConfig::prefer_hashcat
      hashcat_gpu.rs    — Hashcat GPU subprocess (cfg-gated: not compiled with opsec feature)
  overthrone-relay/src/
    relay.rs            — LDAPS TLS wrapping with RelayStream/RelayIo
  overthrone-forge/src/
    acl_backdoor.rs     — RBCD (configure/verify/clear)
  overthrone-hunter/src/
    kerberoast.rs       — KerberoastConfig::downgrade_to_rc4, uses kerberoast_ex
  overthrone-cli/src/
    main.rs             — roast --opsec, crack --hashcat, -U on subcommand userlist only
    commands_impl.rs    — cmd_crack hashcat flag
```
