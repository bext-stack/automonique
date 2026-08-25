// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use automonique_daemon::DaemonConfig;
use automonique_daemon::candidate::{CandidateSpec, spawn_warm_candidate};
use automonique_daemon::release_activation::{CodeReleaseActivator, SystemdUserSupervisor};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

#[test]
fn exact_release_candidate_warms_without_competing_for_source_authority() {
    let root = tempfile::tempdir().expect("temporary root");
    private_directory(root.path());
    let runtime_root = root.path().join("runtime");
    let state_root = root.path().join("state");
    private_directory(&runtime_root);
    private_directory(&state_root);
    let config = DaemonConfig {
        runtime_root,
        state_root,
    };

    let source = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["daemon", "--foreground"])
        .env("XDG_RUNTIME_DIR", &config.runtime_root)
        .env("XDG_STATE_HOME", &config.state_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("source daemon");
    let mut source = ChildGuard(Some(source));
    wait_for_path(&config.admin_socket());
    let (source_holder_id, source_lease_epoch) = read_source_lease(&config.database_path());

    let release_root = root.path().join("code-releases");
    private_directory(&release_root);
    private_directory(&release_root.join("releases"));
    let executable = fs::read(env!("CARGO_BIN_EXE_automonique")).expect("candidate binary");
    let binary_sha256 = hex(&Sha256::digest(&executable));
    let manifest = serde_json::json!({
        "schema": "automonique.code-release/v1",
        "source_sha": "a".repeat(40),
        "plan_digest": format!("sha256:{}", "b".repeat(64)),
        "binary_path": "bin/automonique",
        "binary_sha256": binary_sha256,
        "changed_paths": ["rust/crates/automonique-daemon/src/candidate.rs"]
    });
    let manifest = serde_json::to_vec(&manifest).expect("manifest");
    let manifest_digest = hex(&Sha256::digest(&manifest));
    let release_dir = release_root.join("releases").join(&manifest_digest);
    private_directory(&release_dir);
    private_directory(&release_dir.join("bin"));
    fs::write(release_dir.join("manifest.json"), manifest).expect("manifest file");
    fs::write(release_dir.join("bin/automonique"), executable).expect("binary file");
    fs::set_permissions(
        release_dir.join("manifest.json"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("manifest mode");
    fs::set_permissions(
        release_dir.join("bin/automonique"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("binary mode");

    let activator =
        CodeReleaseActivator::new(&release_root, "automonique.service", SystemdUserSupervisor)
            .expect("activator");
    let digest = format!("sha256:{manifest_digest}");
    let release = activator.verify(&digest).expect("verified release");
    let candidate = spawn_warm_candidate(
        &config,
        &release,
        &CandidateSpec {
            reload_id: "reload-process-test".to_owned(),
            source_holder_id,
            source_lease_epoch,
            target_generation_id: "foreground-next".to_owned(),
            warm_timeout: Duration::from_secs(20),
        },
    )
    .expect("warm candidate");
    assert_ne!(candidate.pid(), source.id());
    candidate.stop().expect("candidate stopped");
    assert!(
        source.try_wait().expect("source status").is_none(),
        "non-owning candidate did not disturb the source daemon"
    );

    kill(source.pid(), Signal::SIGTERM).expect("stop source");
    assert!(source.wait_deadlined(Duration::from_secs(20)).success());
}

fn read_source_lease(path: &Path) -> (String, u64) {
    let connection = Connection::open(path).expect("main database");
    connection
        .query_row(
            "SELECT lease_holder, lease_epoch FROM generations
             WHERE generation_id = 'foreground'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("source lease")
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.exists() {
        assert!(Instant::now() < deadline, "daemon endpoint did not appear");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).expect("private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn id(&self) -> u32 {
        self.0.as_ref().expect("live child").id()
    }

    fn pid(&self) -> Pid {
        Pid::from_raw(i32::try_from(self.id()).expect("PID fits i32"))
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.0.as_mut().expect("live child").try_wait()
    }

    fn wait_deadlined(&mut self, timeout: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait().expect("child status") {
                self.0 = None;
                return status;
            }
            assert!(Instant::now() < deadline, "child did not stop on time");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
