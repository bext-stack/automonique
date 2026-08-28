// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{
    Checkpoint, CheckpointPhase, LedgerSnapshot, StatfsReadback, TemporaryStorageBudget,
};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn restarting_the_owner_process_terminalizes_unrecoverable_live_custody() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("state");
    let runtime = temporary.path().join("runtime");
    let runs = state.join("automonique/runs");
    let run = runs.join("run-1");
    let socket_parent = runtime.join("automonique");
    let cgroup = temporary.path().join("cgroup");
    for directory in [&state, &runtime, &runs, &run, &socket_parent, &cgroup] {
        private_directory(directory);
    }
    let checkpoint_path = run.join(automonique_runner::CHECKPOINT_LEAF);
    let budget = TemporaryStorageBudget::new(8192, 8).unwrap();
    let snapshot = LedgerSnapshot {
        budget,
        used_bytes: 0,
        used_objects: 0,
        peak_bytes: 0,
        peak_objects: 0,
        refused_bytes: 0,
        refused_objects: 0,
        recorded: Vec::new(),
    };
    let statfs = StatfsReadback::from_ledger(&snapshot).unwrap();
    Checkpoint {
        sequence: 41,
        at_millis: 1,
        phase: CheckpointPhase::Live,
        snapshot,
        mount_evidence: "automonique.namespaced-tempfs/v1 owner-restart-proof".to_owned(),
        statfs_at_mount: statfs,
        final_record: None,
    }
    .write(&checkpoint_path)
    .unwrap();
    private_file(
        &run.join(automonique_runner::tempfs_owner::OWNER_TOKEN_LEAF),
        "a".repeat(64).as_bytes(),
    );
    let socket = socket_parent.join("tempfs-owner.sock");
    let cgroup_metadata = fs::symlink_metadata(&cgroup).unwrap();
    let custody = format!(
        "automonique.tempfs-owner/v1 custody {} {} {} {} {} {} {} {}\n",
        hex(b"run-1"),
        hex(socket.as_os_str().as_encoded_bytes()),
        hex(cgroup.as_os_str().as_encoded_bytes()),
        cgroup_metadata.dev(),
        cgroup_metadata.ino(),
        budget.bytes(),
        budget.objects(),
        hex(checkpoint_path.as_os_str().as_encoded_bytes()),
    );
    private_file(
        &run.join(automonique_runner::tempfs_owner::OWNER_CUSTODY_LEAF),
        custody.as_bytes(),
    );

    let child = Command::new(env!("CARGO_BIN_EXE_automonique-launch-enter"))
        .arg(automonique_runner::tempfs_owner::OWNER_MODE_FLAG)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env(automonique_runner::tempfs_owner::OWNER_SOCKET_ENV, &socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(2);
    let final_checkpoint = loop {
        if let Ok(checkpoint) = Checkpoint::read(&checkpoint_path)
            && checkpoint.phase == CheckpointPhase::Final
        {
            break checkpoint;
        }
        assert!(
            Instant::now() < deadline,
            "owner restart did not terminalize"
        );
        std::thread::sleep(Duration::from_millis(10));
    };

    assert_eq!(final_checkpoint.sequence, 42);
    let final_record = final_checkpoint.final_record.unwrap();
    assert!(final_record.aborted);
    assert!(!final_record.unmount_confirmed);
    assert!(
        !run.join(automonique_runner::tempfs_owner::OWNER_TOKEN_LEAF)
            .exists()
    );
    assert!(
        !run.join(automonique_runner::tempfs_owner::OWNER_CUSTODY_LEAF)
            .exists()
    );
}
