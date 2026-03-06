# Contributing to Overthrone

Thank you for your interest in contributing to Overthrone! This guide covers everything
you need to get started.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | 1.85+ | `rustup update stable` |
| Cargo | latest | Ships with Rust |
| Git | 2.x+ | |
| OpenSSL (Linux) | libssl-dev | `sudo apt-get install pkg-config libssl-dev` |
| Samba (macOS) | via Homebrew | `brew install samba pkg-config` |

## Building

```bash
# Clone the repository
git clone https://github.com/Karmanya03/Overthrone.git
cd Overthrone

# Build the entire workspace
cargo build --workspace

# Build only the CLI binary
cargo build -p overthrone

# Release build
cargo build --release -p overthrone
```

## Running Tests

```bash
# Run all workspace tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p overthrone-core
cargo test -p overthrone-pilot
```

## Code Style

We enforce consistent formatting and lint hygiene through CI:

```bash
# Format code (must pass CI)
cargo fmt --all

# Lint with clippy (must pass CI with zero warnings)
cargo clippy --workspace --all-targets -- -D warnings

# Security audit
cargo install cargo-audit
cargo audit
```

### Clippy Thresholds

Our [clippy.toml](clippy.toml) sets:
- `too-many-arguments-threshold = 7` — refactor into a config/params struct
- `type-complexity-threshold = 250` — introduce type aliases for complex types

### Style Conventions

- **No blanket `#![allow(unused, dead_code)]`** — suppress individual items only with a comment explaining why.
- **Error handling** — use `overthrone_core::error::Result<T>` and `OverthroneError` variants.
- **Async** — all network-facing code uses `tokio` async. Use `async fn` and `.await`.
- **Logging** — use `tracing` macros (`info!`, `debug!`, `warn!`, `error!`).

## Workspace Structure

```
crates/
  overthrone-core/     # Protocols, crypto, types, graph engine
  overthrone-reaper/   # Credential harvesting (DCSync, secrets dump)
  overthrone-hunter/   # Enumeration & attacks (Kerberoast, coercion, ADCS)
  overthrone-forge/    # Ticket forging (Golden/Silver/Diamond tickets)
  overthrone-pilot/    # Autonomous attack runner, Q-learning planner
  overthrone-crawler/  # Web crawling & service discovery
  overthrone-scribe/   # Reporting (PDF, JSON, HTML output)
  overthrone-relay/    # NTLM relay & responder
  overthrone-cli/      # CLI binary, TUI, interactive shell
```

## Adding a New Attack Module

1. **Identify the right crate** — protocol logic goes in `overthrone-core`, enumeration/attacks in `overthrone-hunter`, credential harvesting in `overthrone-reaper`.
2. **Create the module file** — e.g. `crates/overthrone-hunter/src/my_attack.rs`.
3. **Register in `mod.rs`** — add `pub mod my_attack;` to the crate's module tree.
4. **Wire into the CLI** — add a `Commands` variant in `crates/overthrone-cli/src/main.rs` and a handler function.
5. **Add tests** — integration tests go in `crates/<crate>/tests/`, unit tests inline with `#[cfg(test)]`.
6. **Document** — add a module doc in `docs/modules/`.

## Fuzz Testing

We maintain fuzz targets under `fuzz/` using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```bash
# Install cargo-fuzz (requires nightly)
rustup install nightly
cargo install cargo-fuzz

# List available fuzz targets
cargo +nightly fuzz list --fuzz-dir fuzz

# Run a fuzz target
cargo +nightly fuzz run fuzz_ntlm_parser --fuzz-dir fuzz

# Just verify fuzz targets compile
cargo +nightly fuzz build --fuzz-dir fuzz
```

Current targets: `fuzz_ntlm_parser`, `fuzz_kerberos_parser`, `fuzz_smb2_parser`.

## Test Coverage

### CI (cargo-tarpaulin)

Coverage runs automatically in CI. To run locally:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --workspace --out Html --output-dir coverage/
# Open coverage/tarpaulin-report.html
```

### Local (cargo-llvm-cov)

For more detailed local coverage:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --html --output-dir coverage/
# Open coverage/html/index.html
```

## Pull Request Process

1. **Fork & branch** — create a feature branch from `main`.
2. **Make changes** — keep commits focused and atomic.
3. **Run the full check suite locally**:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo audit
   ```
4. **Open a PR** — describe what changed and why. Reference any related issues.
5. **CI must pass** — all jobs (test, clippy, fmt, audit) must be green.
6. **Review** — address any feedback promptly.

## Security Disclosures

Overthrone is a red team tool — we take security seriously. If you find a vulnerability
in Overthrone itself (not in the targets it's designed to test), please:

- **Do NOT open a public issue.**
- Email the maintainer directly or use GitHub's private security advisory feature.
- Include steps to reproduce and potential impact.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
