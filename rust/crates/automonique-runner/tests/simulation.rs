// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{
    Authority, CancellationToken, EventKind, RunState, SimulationError, SimulationOutcome,
    SimulationResult, SimulationRunner, SimulationSpec, SimulationSpecError, SimulationSpecParts,
    SimulationStep,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-simulation-{label}-{}-{serial}",
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

fn spec(root: &Path, run_id: &str, steps: &[&[u8]], outcome: SimulationOutcome) -> SimulationSpec {
    SimulationSpec::new(SimulationSpecParts {
        protocol_version: 1,
        run_id: run_id.to_owned(),
        spool_directory: root.join("spool"),
        max_spool_bytes: 1024 * 1024,
        steps: steps
            .iter()
            .map(|payload| SimulationStep::new(payload.to_vec()).unwrap())
            .collect(),
        outcome,
    })
    .unwrap()
}

#[test]
fn success_is_explicitly_synthetic() {
    let root = TempDir::new("success");
    let spec = spec(
        root.path(),
        "simulation-success",
        &[b"first", b"second"],
        SimulationOutcome::success(b"synthetic output".to_vec()).unwrap(),
    );
    let receipt = SimulationRunner
        .run(&spec, &CancellationToken::new(), 0)
        .unwrap();

    assert_eq!(
        receipt.result(),
        &SimulationResult::Succeeded {
            output: b"synthetic output".to_vec()
        }
    );
    assert_eq!(receipt.status().state(), RunState::Completed);
    assert_eq!(receipt.events().len(), 5);
    assert!(
        receipt
            .events()
            .iter()
            .all(|event| event.authority() == Authority::Synthetic)
    );
    assert_eq!(
        receipt
            .events()
            .iter()
            .filter(|event| event.kind() == EventKind::SimulationEvent)
            .count(),
        3
    );
    assert_eq!(terminal_count(receipt.events()), 1);
}

#[test]
fn failure_has_a_typed_deterministic_result_and_one_terminal() {
    let root = TempDir::new("failure");
    let spec = spec(
        root.path(),
        "simulation-failure",
        &[b"only-step"],
        SimulationOutcome::failure(17, b"synthetic failure".to_vec()).unwrap(),
    );
    let receipt = SimulationRunner
        .run(&spec, &CancellationToken::new(), 0)
        .unwrap();

    assert_eq!(
        receipt.result(),
        &SimulationResult::Failed {
            code: 17,
            detail: b"synthetic failure".to_vec()
        }
    );
    assert_eq!(receipt.status().state(), RunState::Failed);
    assert_eq!(terminal_count(receipt.events()), 1);
}

#[test]
fn cancellation_is_recorded_without_running_synthetic_steps() {
    let root = TempDir::new("cancelled");
    let spec = spec(
        root.path(),
        "simulation-cancelled",
        &[b"must-not-be-emitted"],
        SimulationOutcome::success(b"must-not-be-returned".to_vec()).unwrap(),
    );
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let receipt = SimulationRunner.run(&spec, &cancellation, 0).unwrap();

    assert_eq!(receipt.result(), &SimulationResult::Cancelled);
    assert_eq!(receipt.status().state(), RunState::Cancelled);
    assert_eq!(
        receipt
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        vec![
            EventKind::Started,
            EventKind::CancelRequested,
            EventKind::Terminal
        ]
    );
    assert_eq!(terminal_count(receipt.events()), 1);
}

#[test]
fn equal_inputs_produce_byte_identical_spools_and_results() {
    let first = TempDir::new("deterministic-a");
    let second = TempDir::new("deterministic-b");
    let first_spec = spec(
        first.path(),
        "same-simulation",
        &[b"a", b"b"],
        SimulationOutcome::success(b"same".to_vec()).unwrap(),
    );
    let second_spec = spec(
        second.path(),
        "same-simulation",
        &[b"a", b"b"],
        SimulationOutcome::success(b"same".to_vec()).unwrap(),
    );
    let first_receipt = SimulationRunner
        .run(&first_spec, &CancellationToken::new(), 0)
        .unwrap();
    let second_receipt = SimulationRunner
        .run(&second_spec, &CancellationToken::new(), 0)
        .unwrap();

    assert_eq!(first_receipt.result(), second_receipt.result());
    assert_eq!(first_receipt.events(), second_receipt.events());
    assert_eq!(
        fs::read(first_spec.spool_directory().join("events.ndjson")).unwrap(),
        fs::read(second_spec.spool_directory().join("events.ndjson")).unwrap()
    );
}

#[test]
fn crash_tail_is_recovered_and_cursor_replay_is_exact() {
    let root = TempDir::new("replay");
    let spec = spec(
        root.path(),
        "simulation-replay",
        &[b"one", b"two"],
        SimulationOutcome::success(b"done".to_vec()).unwrap(),
    );
    let initial = SimulationRunner
        .run(&spec, &CancellationToken::new(), 0)
        .unwrap();
    let expected = initial.events()[2..].to_vec();
    OpenOptions::new()
        .append(true)
        .open(spec.spool_directory().join("events.ndjson"))
        .unwrap()
        .write_all(b"{\"crash_tail\":")
        .unwrap();

    let resumed = SimulationRunner
        .run(&spec, &CancellationToken::new(), 2)
        .unwrap();
    assert_eq!(resumed.events(), expected);
    assert_eq!(resumed.result(), initial.result());
    assert_eq!(terminal_count(resumed.events()), 1);
}

#[test]
fn payload_that_looks_like_a_command_has_no_external_effect() {
    let root = TempDir::new("inert");
    let marker = root.path().join("must-not-exist");
    let command = format!("/bin/sh -c 'touch {}'", marker.display()).into_bytes();
    let spec = spec(
        root.path(),
        "simulation-inert",
        &[&command],
        SimulationOutcome::success(Vec::new()).unwrap(),
    );

    SimulationRunner
        .run(&spec, &CancellationToken::new(), 0)
        .unwrap();
    assert!(!marker.exists());
    let mut entries = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries, vec!["spool"]);
    let mut spool_entries = fs::read_dir(spec.spool_directory())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    spool_entries.sort();
    assert_eq!(spool_entries, vec!["events.ndjson", "status.json"]);
}

#[test]
fn bounded_input_and_exact_history_identity_are_enforced() {
    let root = TempDir::new("bounds");
    assert_eq!(
        SimulationStep::new(vec![0; 8 * 1024 + 1]).unwrap_err(),
        SimulationSpecError::StepTooLarge
    );
    assert_eq!(
        SimulationOutcome::failure(0, Vec::new()).unwrap_err(),
        SimulationSpecError::FailureCodeInvalid
    );
    let mut parts = SimulationSpecParts {
        protocol_version: 1,
        run_id: "relative".into(),
        spool_directory: PathBuf::from("relative"),
        max_spool_bytes: 1024 * 1024,
        steps: Vec::new(),
        outcome: SimulationOutcome::success(Vec::new()).unwrap(),
    };
    assert_eq!(
        SimulationSpec::new(parts.clone()).unwrap_err(),
        SimulationSpecError::SpoolPathNotAbsolute
    );

    parts.spool_directory = root.path().join("spool");
    let original = SimulationSpec::new(parts.clone()).unwrap();
    SimulationRunner
        .run(&original, &CancellationToken::new(), 0)
        .unwrap();
    parts.outcome = SimulationOutcome::success(b"different".to_vec()).unwrap();
    let changed = SimulationSpec::new(parts).unwrap();
    assert!(matches!(
        SimulationRunner.run(&changed, &CancellationToken::new(), 0),
        Err(SimulationError::HistoryMismatch)
    ));
}

fn terminal_count(events: &[automonique_runner::Event]) -> usize {
    events
        .iter()
        .filter(|event| event.kind() == EventKind::Terminal)
        .count()
}
