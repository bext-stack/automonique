// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use automonique_lab::build::{
    BuildBroker, BuildError, BuildLimits, BuildMutation, BuildOutcome, BuildRequest, Recipe,
};

fn limits() -> BuildLimits {
    BuildLimits {
        wall_ms: 3_000,
        term_grace_ms: 50,
        cpu_seconds: 2,
        output_bytes: 8_192,
        file_bytes: 8_192,
        max_pids: 8,
        max_open_files: 64,
    }
}

fn request(action_id: &str, recipe: Recipe, limits: BuildLimits) -> BuildRequest {
    BuildRequest {
        action_id: action_id.to_owned(),
        recipe,
        limits,
    }
}

fn broker() -> (tempfile::TempDir, PathBuf, BuildBroker) {
    let temporary = tempfile::tempdir().expect("temporary parent");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary parent");
    let root = temporary.path().join("broker");
    let broker = BuildBroker::open(&root).expect("open broker");
    (temporary, root, broker)
}

#[test]
fn fixed_success_has_bounded_receipt_and_private_storage() {
    let (_temporary, root, mut broker) = broker();
    let mutation = broker
        .run(request("success-1", Recipe::Success, limits()))
        .expect("run success");
    let receipt = mutation.receipt();
    assert_eq!(receipt.outcome, BuildOutcome::Success);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(receipt.stdout.starts_with(b"synthetic-build-ok"));
    assert!(receipt.stderr.starts_with(b"synthetic-build-diagnostic"));
    assert!(receipt.stdout.len() + receipt.stderr.len() <= 8_192);
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&root.join("work")), 0o700);
    assert_eq!(mode(&root.join("work/success-1")), 0o700);
    assert_eq!(mode(&root.join("build-state.sqlite3")), 0o600);
    for suffix in ["-wal", "-shm"] {
        let sidecar = root.join(format!("build-state.sqlite3{suffix}"));
        if sidecar.exists() {
            assert_eq!(mode(&sidecar), 0o600);
        }
    }
}

#[test]
fn wall_timeout_terminates_the_fixed_process_group() {
    let (_temporary, _root, mut broker) = broker();
    let mut bounded = limits();
    bounded.wall_ms = 100;
    let started = Instant::now();
    let receipt = broker
        .run(request("wall-1", Recipe::Sleep, bounded))
        .expect("bounded sleep")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::WallLimit);
    assert_eq!(receipt.signal, Some(nix::libc::SIGKILL));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn cpu_limit_is_reported_from_the_kernel_signal() {
    let (_temporary, _root, mut broker) = broker();
    let mut bounded = limits();
    bounded.cpu_seconds = 1;
    bounded.wall_ms = 5_000;
    let receipt = broker
        .run(request("cpu-1", Recipe::CpuHog, bounded))
        .expect("bounded CPU")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::CpuLimit);
}

#[test]
fn combined_output_is_truncated_and_terminates_the_group() {
    let (_temporary, _root, mut broker) = broker();
    let mut bounded = limits();
    bounded.output_bytes = 1_024;
    let receipt = broker
        .run(request("output-1", Recipe::OutputFlood, bounded))
        .expect("bounded output")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::OutputLimit);
    assert!(receipt.stdout.len() + receipt.stderr.len() <= 1_024);
}

#[test]
fn file_size_and_open_file_limits_are_enforced() {
    let (_temporary, root, mut broker) = broker();
    let mut disk = limits();
    disk.file_bytes = 1_024;
    let receipt = broker
        .run(request("disk-1", Recipe::DiskFlood, disk))
        .expect("bounded disk")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::DiskLimit);
    assert!(
        fs::metadata(root.join("work/disk-1/artifact.bin"))
            .unwrap()
            .len()
            <= 1_024
    );

    let mut descriptors = limits();
    descriptors.max_open_files = 8;
    let receipt = broker
        .run(request("files-1", Recipe::OpenFiles, descriptors))
        .expect("bounded descriptors")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::FileCountLimit);
    let aggregate: u64 = fs::read_dir(root.join("work/files-1"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum();
    assert!(aggregate <= descriptors.file_bytes);
}

#[test]
fn declared_pid_requirement_fails_closed_before_spawn() {
    let (_temporary, root, mut broker) = broker();
    let mut bounded = limits();
    bounded.cpu_seconds = 4;
    bounded.max_pids = 3;
    let receipt = broker
        .run(request("pid-1", Recipe::PidBurst, bounded))
        .expect("PID refusal")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::PidLimit);
    assert_eq!(receipt.wall_ms, 0);
    assert!(
        fs::read_dir(root.join("work/pid-1"))
            .unwrap()
            .next()
            .is_none()
    );

    bounded.max_pids = 4;
    bounded.wall_ms = 10_000;
    let receipt = broker
        .run(request("pid-2", Recipe::PidBurst, bounded))
        .expect("declared PID budget")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::CpuLimit);
}

#[test]
fn timeout_cleans_up_a_spawned_descendant() {
    let (_temporary, _root, mut broker) = broker();
    let mut bounded = limits();
    bounded.wall_ms = 100;
    let receipt = broker
        .run(request("tree-1", Recipe::Descendant, bounded))
        .expect("bounded descendant")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::WallLimit);
    let line = std::str::from_utf8(&receipt.stdout).expect("fixture output");
    let pids = line
        .trim()
        .strip_prefix("descendant-pids:")
        .expect("descendant PIDs")
        .split(',')
        .collect::<Vec<_>>();
    for pid in pids {
        let process = PathBuf::from(format!("/proc/{pid}"));
        let deadline = Instant::now() + Duration::from_secs(2);
        while process.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !process.exists(),
            "descendant remained after process-group cleanup"
        );
    }

    let mut pid_bounded = limits();
    pid_bounded.max_pids = 2;
    let receipt = broker
        .run(request("tree-2", Recipe::Descendant, pid_bounded))
        .expect("monitored descendant overflow")
        .receipt()
        .clone();
    assert_eq!(receipt.outcome, BuildOutcome::PidLimit);
}

#[test]
fn completed_action_replays_and_changed_request_is_denied() {
    let (_temporary, root, mut broker) = broker();
    let original = request("replay-1", Recipe::Success, limits());
    let first = broker.run(original.clone()).expect("first run");
    assert!(matches!(first, BuildMutation::Applied(_)));
    drop(broker);
    let mut reopened = BuildBroker::open(&root).expect("reopen completed broker");
    let second = reopened.run(original).expect("exact replay after restart");
    assert!(matches!(second, BuildMutation::Replayed(_)));
    assert_eq!(first.receipt(), second.receipt());
    assert!(matches!(
        reopened.run(request("replay-1", Recipe::Sleep, limits())),
        Err(BuildError::IdempotencyConflict)
    ));
}

#[test]
fn prepared_work_runs_once_but_ambiguous_started_work_is_refused_after_restart() {
    let (_temporary, root, mut broker) = broker();
    let prepared = request("interrupted-1", Recipe::Success, limits());
    broker.prepare(prepared.clone()).expect("persist intent");
    let applied = broker.run(prepared.clone()).expect("execute prepared work");
    assert!(matches!(applied, BuildMutation::Applied(_)));
    drop(broker);
    let mut reopened = BuildBroker::open(&root).expect("reopen broker");
    assert!(matches!(
        reopened.run(prepared),
        Ok(BuildMutation::Replayed(_))
    ));

    let ambiguous = request("interrupted-2", Recipe::Success, limits());
    reopened
        .prepare(ambiguous.clone())
        .expect("prepare unknown outcome");
    drop(reopened);
    let connection = rusqlite::Connection::open(root.join("build-state.sqlite3")).unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE build_actions SET state = 'running' WHERE action_id = 'interrupted-2'",
                [],
            )
            .unwrap(),
        1
    );
    drop(connection);
    let mut reopened = BuildBroker::open(&root).expect("reopen ambiguous broker");
    assert!(matches!(
        reopened.run(ambiguous),
        Err(BuildError::InterruptedIntent)
    ));
}

#[test]
fn invalid_ids_limits_and_symlink_roots_are_denied() {
    let (_temporary, root, mut broker) = broker();
    assert!(matches!(
        broker.run(request("-leading", Recipe::Success, limits())),
        Err(BuildError::InvalidActionId)
    ));
    let mut invalid = limits();
    invalid.output_bytes = 0;
    assert!(matches!(
        broker.run(request("invalid-1", Recipe::Success, invalid)),
        Err(BuildError::InvalidLimits)
    ));
    let redirected = root.join("work/redirected");
    fs::create_dir(&redirected).unwrap();
    symlink(&redirected, root.join("work/linked-action")).unwrap();
    assert!(matches!(
        broker.run(request("linked-action", Recipe::Success, limits())),
        Err(BuildError::UnsafePath(_))
    ));

    let temporary = tempfile::tempdir().unwrap();
    let real = temporary.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = temporary.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(matches!(
        BuildBroker::open(&link),
        Err(BuildError::UnsafePath(_))
    ));

    let database_root = temporary.path().join("database-root");
    fs::create_dir(&database_root).unwrap();
    fs::set_permissions(&database_root, fs::Permissions::from_mode(0o700)).unwrap();
    let target = temporary.path().join("database-target");
    fs::write(&target, []).unwrap();
    symlink(&target, database_root.join("build-state.sqlite3")).unwrap();
    assert!(matches!(
        BuildBroker::open(&database_root),
        Err(BuildError::UnsafePath(_))
    ));

    let root_mode = mode(Path::new("/"));
    assert!(matches!(
        BuildBroker::open("/"),
        Err(BuildError::UnsafePath(_))
    ));
    assert_eq!(mode(Path::new("/")), root_mode);

    let temporary_mode = mode(Path::new("/tmp"));
    assert!(matches!(
        BuildBroker::open("/tmp"),
        Err(BuildError::UnsafePath(_))
    ));
    assert_eq!(mode(Path::new("/tmp")), temporary_mode);

    let permissive = temporary.path().join("permissive");
    fs::create_dir(&permissive).unwrap();
    fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        BuildBroker::open(&permissive),
        Err(BuildError::UnsafePath(_))
    ));
    assert_eq!(mode(&permissive), 0o755);
    let missing = permissive.join("missing");
    assert!(matches!(
        BuildBroker::open(&missing),
        Err(BuildError::UnsafePath(_))
    ));
    assert!(!missing.exists());
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}
