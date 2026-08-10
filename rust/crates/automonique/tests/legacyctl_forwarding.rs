// SPDX-License-Identifier: Elastic-2.0

use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn runtime(with_product_directory: bool) -> tempfile::TempDir {
    let runtime = tempfile::tempdir().expect("temporary runtime directory");
    #[cfg(unix)]
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private XDG runtime directory");
    if with_product_directory {
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
    }
    runtime
}

fn run(binary: &str, runtime: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .env("XDG_RUNTIME_DIR", runtime)
        .env_remove("AUTOMONIQUE_RUNTIME_DIR")
        .env_remove("AUTOMONIQUE_CONFIG")
        .env_remove("AUTOMONIQUE_HOME")
        .output()
        .expect("product command starts")
}

fn assert_exact_forwarding(runtime: &Path, args: &[&str], expected_exit: i32) {
    let canonical = run(env!("CARGO_BIN_EXE_automonique"), runtime, args);
    let legacy = run(env!("CARGO_BIN_EXE_legacyctl"), runtime, args);

    assert_eq!(canonical.status.code(), Some(expected_exit));
    assert_eq!(legacy.status.code(), canonical.status.code());
    assert_eq!(legacy.stdout, canonical.stdout);
    assert_eq!(legacy.stderr, canonical.stderr);
}

#[test]
fn metadata_safe_doctor_human_and_json_match_byte_for_byte() {
    let runtime = runtime(true);
    assert_exact_forwarding(runtime.path(), &["doctor"], 1);
    assert_exact_forwarding(runtime.path(), &["doctor", "--json"], 1);
}

#[test]
fn unavailable_doctor_human_and_json_match_byte_for_byte() {
    let runtime = runtime(false);
    let product = runtime.path().join("automonique");
    assert_exact_forwarding(runtime.path(), &["doctor"], 1);
    assert_exact_forwarding(runtime.path(), &["doctor", "--json"], 1);
    assert!(!product.exists());
}

#[test]
fn invalid_invocations_match_byte_for_byte() {
    let runtime = runtime(true);
    for arguments in [&[][..], &["status"][..], &["doctor", "--fix"][..]] {
        assert_exact_forwarding(runtime.path(), arguments, 2);
    }
}
