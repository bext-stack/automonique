// SPDX-License-Identifier: Elastic-2.0

//! Test-support guard: a test's runtime root must not be the host's.
//!
//! The daemon binds its admin socket at `<runtime_root>/automonique/admin.sock`,
//! and the CLI resolves the same path from `XDG_RUNTIME_DIR`. A test that let
//! either resolve the *ambient* runtime directory would drive the host's real
//! daemon — the production incident class this guard exists for: an orderly
//! drain of the live daemon, requested by nothing an operator did. Every test
//! fixture therefore asserts, at the moment it creates its runtime root, that
//! the root is not the ambient `XDG_RUNTIME_DIR` and not under `/run/user`,
//! the kernel's real per-user runtime tree; and every helper that spawns a
//! CLI or daemon asserts the same about the root it is about to export.
//!
//! The check is deliberately exact rather than prefix-based: a temporary root
//! under `/tmp` while `XDG_RUNTIME_DIR=/tmp` collides nothing — the sockets
//! live at `<root>/automonique/admin.sock` — so only an *equal* root, or one
//! inside the real `/run/user` tree, is refused.
//!
//! An identical copy serves the `automonique` crate's tests at
//! `crates/automonique/tests/support/isolation.rs`; integration-test binaries
//! cannot share modules across crates.

use std::path::{Path, PathBuf};

/// Panic unless `runtime_root` is private to this test.
pub fn assert_isolated_runtime_root(runtime_root: &Path) {
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let root = canonical(runtime_root);
    assert!(
        !root.starts_with("/run/user"),
        "test runtime root {} is under /run/user, the host's real runtime tree; \
         a daemon or CLI pointed there reaches the real admin socket — use a \
         private temporary directory",
        root.display()
    );
    if let Some(ambient) = std::env::var_os("XDG_RUNTIME_DIR") {
        let ambient = canonical(&PathBuf::from(ambient));
        assert!(
            root != ambient,
            "test runtime root {} is the ambient XDG_RUNTIME_DIR; a daemon or CLI \
             pointed there reaches the host's real admin socket — use a private \
             temporary directory",
            root.display()
        );
    }
}
