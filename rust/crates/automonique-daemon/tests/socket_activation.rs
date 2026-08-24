// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};

const CHILD_MARKER: &str = "AUTOMONIQUE_SOCKET_ACTIVATION_CHILD";
const RUNTIME_ROOT: &str = "AUTOMONIQUE_SOCKET_ACTIVATION_RUNTIME_ROOT";
const STATE_ROOT: &str = "AUTOMONIQUE_SOCKET_ACTIVATION_STATE_ROOT";

#[test]
fn daemon_adopts_the_one_named_systemd_listener_without_unlinking_it() {
    if std::env::var_os(CHILD_MARKER).is_some() {
        child_adopts_listener();
        return;
    }

    let root = tempfile::tempdir().expect("temporary root");
    private_directory(root.path());
    let runtime_root = root.path().join("runtime");
    let state_root = root.path().join("state");
    let runtime_dir = runtime_root.join("automonique");
    private_directory(&runtime_root);
    private_directory(&state_root);
    private_directory(&runtime_dir);
    let socket_path = runtime_dir.join("admin.sock");
    let mut launcher = Command::new("systemd-socket-activate");
    launcher
        .arg("--listen")
        .arg(&socket_path)
        .arg("--fdname=admin")
        .arg("--setenv")
        .arg(format!("{CHILD_MARKER}=1"))
        .arg("--setenv")
        .arg(format!("{RUNTIME_ROOT}={}", runtime_root.display()))
        .arg("--setenv")
        .arg(format!("{STATE_ROOT}={}", state_root.display()))
        .arg(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("daemon_adopts_the_one_named_systemd_listener_without_unlinking_it")
        .arg("--nocapture");
    let child = launcher.spawn().expect("socket activation launcher");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket_path.exists() {
        assert!(
            Instant::now() < deadline,
            "launcher did not bind the socket"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .expect("private socket mode");
    drop(UnixStream::connect(&socket_path).expect("trigger socket activation"));
    let output = child.wait_with_output().expect("activation child");
    assert!(
        output.status.success(),
        "activation child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        socket_path.exists(),
        "the daemon must not unlink a socket owned by systemd"
    );
}

fn child_adopts_listener() {
    let config = DaemonConfig {
        runtime_root: required_path(RUNTIME_ROOT),
        state_root: required_path(STATE_ROOT),
    };
    let socket_path = config.admin_socket();
    let before = std::fs::symlink_metadata(&socket_path).expect("activated socket metadata");
    let daemon = Daemon::open(&config).expect("daemon adopts activated listener");
    drop(daemon);
    let after = std::fs::symlink_metadata(&socket_path).expect("socket remains after daemon drop");
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
}

fn private_directory(path: &Path) {
    std::fs::create_dir_all(path).expect("private directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("private directory mode");
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("missing {name}"))
}
