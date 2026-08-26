// SPDX-License-Identifier: Elastic-2.0

//! The isolation guard's own proofs: what it permits, and what it refuses.
//!
//! Every daemon and CLI test fixture in this crate calls
//! `assert_isolated_runtime_root` when it creates its runtime root, so what
//! the guard refuses can never bind — or drive — the host's real admin
//! socket. These tests pin the rule itself.

#[path = "support/isolation.rs"]
mod test_isolation;

use test_isolation::assert_isolated_runtime_root;

#[test]
fn a_private_temporary_runtime_root_is_permitted() {
    let root = tempfile::tempdir().expect("temporary root");
    let runtime = root.path().join("runtime");
    std::fs::create_dir(&runtime).expect("runtime root");
    assert_isolated_runtime_root(&runtime);
    // Before creation the path cannot be canonicalized; the guard must still
    // judge it rather than wave it through.
    assert_isolated_runtime_root(&root.path().join("not-created-yet"));
}

#[test]
#[should_panic(expected = "/run/user")]
fn the_real_per_user_runtime_tree_is_refused() {
    use std::os::unix::fs::MetadataExt as _;
    let uid = std::fs::metadata("/proc/self")
        .expect("own process metadata")
        .uid();
    assert_isolated_runtime_root(std::path::Path::new(&format!("/run/user/{uid}")));
}

#[test]
#[should_panic(expected = "admin socket")]
fn the_ambient_runtime_directory_is_refused() {
    // The guard reads the ambient value itself. Both of its refusals — the
    // ambient match and the /run/user tree, whichever fires first — name the
    // admin socket the root could have reached; an environment that carries
    // no ambient value at all has nothing to refuse, and says so in the same
    // words so the expectation holds everywhere.
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(ambient) => assert_isolated_runtime_root(std::path::Path::new(&ambient)),
        None => panic!("no ambient runtime directory could reach a real admin socket here"),
    }
}
