// SPDX-License-Identifier: Elastic-2.0

use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
fn doctor_human_mode_reports_unavailable_rpcs_for_a_private_runtime() {
    let runtime = private_runtime();
    let output = run(runtime.path(), &["doctor"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("degraded"), "{stdout}");
    assert!(
        stdout.contains("database.health-rpc-unavailable"),
        "{stdout}"
    );
    assert!(stdout.contains("release.missing"), "{stdout}");
    assert!(stdout.contains("release.manifest-structure"), "{stdout}");
    assert!(
        stdout.contains("supervisor.configuration-unavailable"),
        "{stdout}"
    );
    assert!(stdout.contains("runtime"), "{stdout}");
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
    assert!(stdout.contains("\"status\":\"degraded\""), "{stdout}");
    assert!(
        stdout.contains("\"code\":\"database.health-rpc-unavailable\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"code\":\"release.missing\""), "{stdout}");
    assert!(
        stdout.contains("\"id\":\"release.manifest-structure\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"id\":\"supervisor.adapter\""), "{stdout}");
    assert!(
        stdout.contains("\"code\":\"supervisor.configuration-unavailable\""),
        "{stdout}"
    );
}

#[test]
fn unsupported_argv_is_usage_error_without_doctor_output() {
    let runtime = private_runtime();
    for args in [
        &[][..],
        &["doctor", "--fix"][..],
        &["shutdown", "--force"][..],
    ] {
        let output = run(runtime.path(), args);
        assert_eq!(output.status.code(), Some(2), "argv: {args:?}");
        assert!(output.stdout.is_empty(), "argv: {args:?}");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
        assert!(stderr.contains("usage"), "argv: {args:?}: {stderr}");
    }
}
