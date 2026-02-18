//! `ovt` — shorthand alias for the `overthrone` binary.
//! This file exists solely to give Cargo a separate entry point
//! so both [[bin]] targets do not share the same source file
//! (which triggers a build warning).
//!
//! All real logic lives in `crates/overthrone-cli/src/main.rs`.
//! Both binaries are functionally identical.

// Re-export the real main by including the shared source.
// We use `#[path]` to point directly at the upstream main.rs.
#[path = "../main.rs"]
mod main_impl;

fn main() {
    // Delegate to the tokio runtime declared in main.rs.
    // Because main.rs uses #[tokio::main], we just call its
    // generated async runtime entry via a re-exported shim.
    main_impl::main()
}
