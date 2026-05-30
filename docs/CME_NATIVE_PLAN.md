CrackMapExec (CME)-style native implementation plan for Overthrone

Goal

Provide native, Rust-based parity with common CrackMapExec/netexec features, integrated into Overthrone's existing execution primitives (WinRM, PsExec, SMBExec, WMI, AtExec, C2).

Scope (prioritized)

1. Module framework (plugin-like builtin modules)
   - Module trait + registry (done in exec/modules.rs)
   - Ability to list and run modules via CLI
2. Native exec modules (priority order)
   - `winrm-exec` (already present as builtin example)
   - `smb-exec` / `psexec` wrappers that expose targeted module interface
   - `wmi-exec` wrapper
   - `procdump` / `lsassy` style modules that use remote execution to dump LSASS
   - `gpp` / `laps` / `kerberos` data collectors (reaper/hunter integration)
3. Scanning & orchestration
   - Multi-target parallel scanning with configurable concurrency
   - Output formats: JSON, CSV, human; per-target results aggregated
4. Module lifecycle
   - Module registration at startup
   - Module discovery (`ovt module list`) and invocation (`ovt module run <name> --target X`)
   - Plugin loading (WASM / dynamic) — future
5. Post-implementation
   - Tests (unit + integration for modules using local mocks)
   - CLI ergonomics & docs (`COMMAND-LIST.md` updates)

Next concrete work items

- Wire `exec/modules` into CLI commands (ovt module list / run) and register builtins at startup.
- Implement `smb-exec` module that wraps `smbexec::SmbExecutor` and provides parameters for `command`, `drop`, `timeout`.
- Implement `procdump` and `lsassy` modules that use remote execution to run procdump and collect LSASS memory, then parse with existing secretsdump primitives.
- Add concurrency and result aggregation to pilot/autopwn flows to use modules in parallel.

Notes

- Preference: avoid external tool wrappers where native implementations exist. Where a third-party binary is required (procdump), prefer to ship a small Rust port or re-implement required functionality; otherwise use on-target execution with built-in uploader and downloader.
- Security: modules will reuse existing ExecCredentials, and must honor stealth/cleanup options.


