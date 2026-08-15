// SPDX-License-Identifier: Elastic-2.0

//! The daemon and the CLI must agree where the audit chain lives.
//!
//! `automonique-cli` does not depend on `automonique-daemon` — it reads durable
//! databases directly, as the parity verbs do — so it pins the file name by
//! literal. This crate is the only one that sees both spellings, which makes it
//! the only place the two can be checked against each other.
//!
//! The cost of them drifting is specific and quiet: `doctor` would look in a
//! directory with no chain in it, find nothing, and report `audit.chain-absent`
//! on a host whose chain is broken. A check that reads healthy because it was
//! pointed at the wrong file is worse than no check.

use std::path::Path;

use automonique_daemon::{AUDIT_CHAIN_NAME, DaemonConfig};

#[test]
fn the_cli_and_the_daemon_name_the_same_audit_chain_file() {
    assert_eq!(automonique_cli::AUDIT_CHAIN_NAME, AUDIT_CHAIN_NAME);
}

#[test]
fn the_audit_chain_sits_beside_the_other_durable_state() {
    let config = DaemonConfig {
        runtime_root: Path::new("/run/user/1000").to_path_buf(),
        state_root: Path::new("/home/operator/.local/state").to_path_buf(),
    };
    let path = config.audit_chain_path();
    assert_eq!(path.parent(), Some(config.state_dir().as_path()));
    assert_eq!(
        path.file_name().and_then(std::ffi::OsStr::to_str),
        Some(AUDIT_CHAIN_NAME)
    );

    // The path `doctor` derives from XDG_STATE_HOME must be the same one, or
    // the check and the daemon are looking at different files.
    let from_environment = Path::new("/home/operator/.local/state")
        .join("automonique")
        .join(automonique_cli::AUDIT_CHAIN_NAME);
    assert_eq!(path, from_environment);
}
