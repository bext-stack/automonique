// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{
    Authority, CancellationToken, ContainmentEvidence, EventKind, PromptDelivery, RunSpec,
    RunSpecError, RunSpecParts, Runner, RunnerError, Spool, SpoolError,
};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-runner-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn parts(root: &Path, prompt: PromptDelivery) -> RunSpecParts {
    RunSpecParts {
        protocol_version: 1,
        work_id: "work-1".into(),
        run_id: "run-1".into(),
        attempt_id: "attempt-1".into(),
        host_id: "host-1".into(),
        executable: PathBuf::from("/bin/true"),
        arguments: Vec::new(),
        cwd: root.to_path_buf(),
        environment: Vec::new(),
        prompt,
        timeout: Duration::from_secs(5),
        term_grace: Duration::from_millis(25),
        spool_directory: root.join("spool"),
        max_spool_bytes: 1024 * 1024,
    }
}

#[test]
fn strict_run_spec_validation_rejects_unbounded_and_ambiguous_values() {
    let root = TempDir::new("validation");
    let prompt = PromptDelivery::stdin(b"hello".to_vec()).unwrap();
    let mut candidate = parts(root.path(), prompt.clone());
    candidate.protocol_version = 2;
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::UnsupportedProtocol(2)
    );

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.run_id = "bad\nrun".into();
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("run_id")
    );

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.cwd = PathBuf::from("relative");
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::PathNotAbsolute("cwd")
    );

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.arguments = vec![OsString::from("x".repeat(4097))];
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::ArgumentTooLarge
    );

    let mut candidate = parts(root.path(), prompt);
    candidate.environment = vec![("BAD=KEY".into(), "value".into())];
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::EnvironmentKeyInvalid
    );

    assert_eq!(
        PromptDelivery::stdin(vec![0; 1024 * 1024 + 1]).unwrap_err(),
        RunSpecError::PromptTooLarge
    );
}

#[test]
fn arbitrary_execution_is_refused_without_descendant_complete_containment() {
    let root = TempDir::new("containment-refusal");
    let spec = RunSpec::new(parts(
        root.path(),
        PromptDelivery::stdin(b"must not execute".to_vec()).unwrap(),
    ))
    .unwrap();
    assert!(matches!(
        Runner.run(spec, &CancellationToken::new()),
        Err(RunnerError::ContainmentUnenforced(
            ContainmentEvidence::ProcessGroupOnly
        ))
    ));
    assert!(!root.path().join("spool").exists());
}

#[test]
fn event_sequences_are_monotonic_and_terminal_is_exactly_once() {
    let root = TempDir::new("terminal");
    let mut spool = Spool::open(root.path().join("spool"), "run-terminal", 1024 * 1024).unwrap();
    spool
        .append(EventKind::Started, Authority::Synthetic, b"start")
        .unwrap();
    spool
        .append(EventKind::Terminal, Authority::Authoritative, b"completed")
        .unwrap();
    let events = spool.events_after(0).unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() == EventKind::Terminal)
            .count(),
        1
    );
    assert_eq!(spool.status().last_sequence(), 2);
    assert!(matches!(
        spool.append(EventKind::AdapterEvent, Authority::Authoritative, b"late"),
        Err(SpoolError::AlreadyTerminal)
    ));
}

#[test]
fn restart_reconstructs_cursor() {
    let root = TempDir::new("cursor");
    {
        let mut spool = Spool::open(root.path().join("spool"), "run-cursor", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
        spool
            .append(EventKind::AdapterEvent, Authority::Authoritative, b"one")
            .unwrap();
    }
    let resumed = Spool::open(root.path().join("spool"), "run-cursor", 1024 * 1024).unwrap();
    assert_eq!(
        resumed
            .events_after(1)
            .unwrap()
            .iter()
            .map(|event| event.sequence())
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert!(matches!(
        resumed.events_after(3),
        Err(SpoolError::CursorAhead { .. })
    ));
}

#[test]
fn restart_discards_only_an_incomplete_crash_tail() {
    let root = TempDir::new("partial-tail");
    let spool_root = root.path().join("spool");
    {
        let mut spool = Spool::open(&spool_root, "run-tail", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
    }
    OpenOptions::new()
        .append(true)
        .open(spool_root.join("events.ndjson"))
        .unwrap()
        .write_all(b"{\"protocol\":\"automonique.runner.event\"")
        .unwrap();

    let mut resumed = Spool::open(&spool_root, "run-tail", 1024 * 1024).unwrap();
    assert_eq!(resumed.events_after(0).unwrap().len(), 1);
    assert_eq!(
        resumed
            .append(EventKind::Terminal, Authority::Authoritative, b"completed")
            .unwrap()
            .sequence(),
        2
    );
}

#[test]
fn complete_frame_payload_mutation_is_refused_by_hash_chain() {
    let root = TempDir::new("mutated-frame");
    let spool_root = root.path().join("spool");
    {
        let mut spool = Spool::open(&spool_root, "run-mutated", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
        spool
            .append(EventKind::AdapterEvent, Authority::Authoritative, b"safe")
            .unwrap();
    }
    let path = spool_root.join("events.ndjson");
    let original = fs::read_to_string(&path).unwrap();
    let lines = original.lines().collect::<Vec<_>>();
    let first_digest = field(lines[0], "sha256");
    assert_eq!(field(lines[1], "previous_sha256"), first_digest);
    let mutated = original.replacen("73616665", "73616664", 1);
    assert_ne!(mutated, original);
    fs::write(&path, mutated).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        Spool::open(&spool_root, "run-mutated", 1024 * 1024),
        Err(SpoolError::Corrupt)
    ));
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    let marker = format!("\"{name}\":\"");
    line.split_once(&marker)
        .and_then(|(_, rest)| rest.split_once('\"'))
        .map(|(value, _)| value)
        .unwrap()
}

#[test]
fn stale_status_temporary_does_not_block_restart() {
    let root = TempDir::new("stale-status");
    let spool_root = root.path().join("spool");
    {
        let mut spool = Spool::open(&spool_root, "run-status", 1024 * 1024).unwrap();
        spool
            .append(EventKind::Started, Authority::Synthetic, b"start")
            .unwrap();
    }
    fs::write(
        spool_root.join(format!(".status.{}.tmp", std::process::id())),
        b"partial",
    )
    .unwrap();
    let reopened = Spool::open(&spool_root, "run-status", 1024 * 1024).unwrap();
    assert_eq!(reopened.status().last_sequence(), 1);
}
