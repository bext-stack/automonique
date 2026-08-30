// SPDX-License-Identifier: Elastic-2.0

use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[path = "support/isolation.rs"]
mod test_isolation;

fn private_runtime() -> tempfile::TempDir {
    let runtime = tempfile::tempdir().expect("temporary runtime directory");
    #[cfg(unix)]
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private XDG runtime directory");
    let product = runtime.path().join("automonique");
    std::fs::create_dir(&product).expect("product runtime directory");
    #[cfg(unix)]
    std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
        .expect("private product runtime directory");
    #[cfg(unix)]
    {
        let socket = product.join("admin.sock");
        let _listener = UnixListener::bind(&socket).expect("admin socket");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("private admin socket");
    }
    runtime
}

fn run(runtime: &Path, args: &[&str]) -> Output {
    test_isolation::assert_isolated_runtime_root(runtime);
    let mut command = Command::new(env!("CARGO_BIN_EXE_automonique"));
    command
        .args(args)
        .env("XDG_RUNTIME_DIR", runtime)
        .env_remove("AUTOMONIQUE_RUNTIME_DIR")
        .env_remove("AUTOMONIQUE_CONFIG")
        .env_remove("AUTOMONIQUE_HOME");
    command.output().expect("automonique starts")
}

#[test]
fn doctor_human_mode_reports_an_unanswered_status_rpc_for_a_private_runtime() {
    let runtime = private_runtime();
    let output = run(runtime.path(), &["doctor"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    // The overall status follows the protocol's aggregation contract rather
    // than a host-specific constant: any finding fails the report, while
    // unavailable checks alone only degrade it. The kernel delegation check
    // legitimately differs between a delegated service and an interactive
    // session, so pinning one word here would pin the test to one host shape.
    if stdout.contains(": finding (") {
        assert!(stdout.contains("failed"), "{stdout}");
    } else {
        assert!(stdout.contains("degraded"), "{stdout}");
    }
    assert!(
        stdout.contains("database.status-rpc-unavailable"),
        "{stdout}"
    );
    assert!(stdout.contains("release.missing"), "{stdout}");
    assert!(stdout.contains("release.manifest-structure"), "{stdout}");
    assert!(
        stdout.contains("supervisor.socket-readback-unavailable"),
        "{stdout}"
    );
    assert!(stdout.contains("runtime"), "{stdout}");
    assert!(stdout.contains("state.filesystem"), "{stdout}");
    // The kernel checks landed with the truthful Landlock/delegation work and
    // must not silently vanish from the assembled report.
    assert!(stdout.contains("kernel.landlock-support"), "{stdout}");
    assert!(stdout.contains("kernel.cgroup-v2.delegation"), "{stdout}");
}

#[test]
fn doctor_json_mode_uses_the_versioned_schema() {
    let runtime = private_runtime();
    let output = run(runtime.path(), &["doctor", "--json"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(
        stdout.contains("\"schema\":\"automonique.doctor/v1\""),
        "{stdout}"
    );
    // Same aggregation contract as the human-mode test: findings fail the
    // report, unavailable checks alone degrade it.
    if stdout.contains("\"status\":\"finding\"") {
        assert!(stdout.contains("\"status\":\"failed\""), "{stdout}");
    } else {
        assert!(stdout.contains("\"status\":\"degraded\""), "{stdout}");
    }
    assert!(
        stdout.contains("\"code\":\"database.status-rpc-unavailable\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"code\":\"release.missing\""), "{stdout}");
    assert!(
        stdout.contains("\"id\":\"release.manifest-structure\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"id\":\"supervisor.adapter\""), "{stdout}");
    assert!(
        stdout.contains("\"code\":\"supervisor.socket-readback-unavailable\""),
        "{stdout}"
    );
}

/// The revision must come out of the binary, not out of anything beside it.
///
/// `run()` hands the child an isolated runtime directory and strips every
/// product environment variable, and the binary is invoked from cargo's target
/// directory where no manifest exists. Anything it reports here it is carrying
/// itself.
#[test]
fn build_identity_names_this_build_without_reading_anything_beside_it() {
    let runtime = private_runtime();
    let output = run(runtime.path(), &["build-identity", "--json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(
        stdout.contains("\"schema\":\"automonique.build-identity/v1\""),
        "{stdout}"
    );
    // The build environment of a test run is not fixed — a clean checkout, a
    // modified worktree and a source tree with no git metadata are all
    // legitimate — so what is pinned is the coherence of the pair, which is the
    // property the whole surface exists for. A build that cannot name a
    // revision says so with an explicit null; it never fills the gap.
    if stdout.contains("\"provenance\":\"unknown\"") {
        assert!(stdout.contains("\"source_revision\":null"), "{stdout}");
    } else {
        assert!(!stdout.contains("\"source_revision\":null"), "{stdout}");
        assert!(
            ["\"declared\"", "\"committed\"", "\"modified\""]
                .iter()
                .any(|provenance| stdout.contains(&format!("\"provenance\":{provenance}"))),
            "{stdout}"
        );
    }

    let human = run(runtime.path(), &["build-identity"]);
    assert_eq!(human.status.code(), Some(0));
    let human = String::from_utf8(human.stdout).expect("UTF-8 output");
    assert!(human.contains("source revision: "), "{human}");
    assert!(human.contains("provenance: "), "{human}");
    assert!(human.contains("build target: "), "{human}");
}

/// The report carries the build's own account of itself beside the manifest one.
///
/// Two checks rather than one, because they fail independently: a host can have
/// no manifest and a perfectly attributable binary, or a manifest describing
/// some other build entirely. Collapsing them would hide whichever half is
/// still standing.
#[test]
fn doctor_reports_build_identity_and_manifest_attribution_separately() {
    let runtime = private_runtime();
    let output = run(runtime.path(), &["doctor"]);
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");

    assert!(stdout.contains("release.build-identity"), "{stdout}");
    assert!(stdout.contains("release.manifest-structure"), "{stdout}");
    // Cargo's target directory holds no release manifest, and the check says so
    // rather than reporting a healthy release it never found.
    assert!(stdout.contains("release.missing"), "{stdout}");
}

#[test]
fn unsupported_argv_is_usage_error_without_doctor_output() {
    let runtime = private_runtime();
    for args in [
        &[][..],
        &["doctor", "--fix"][..],
        &["build-identity", "--verbose"][..],
        &["shutdown", "--force"][..],
    ] {
        let output = run(runtime.path(), args);
        assert_eq!(output.status.code(), Some(2), "argv: {args:?}");
        assert!(output.stdout.is_empty(), "argv: {args:?}");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
        assert!(stderr.contains("usage"), "argv: {args:?}: {stderr}");
    }
}
