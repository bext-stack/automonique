// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::sandbox::ExecutionBackendId;
use automonique_protocol::tools::RunId;
use automonique_runner::{
    Authority, BackendPromptSession, CancellationToken, ContainmentEvidence, EventKind,
    PromptDeliveryPlan, ProtectedPromptReference, RunCoordinates, RunSpec, RunSpecError,
    RunSpecParts, Runner, RunnerError, Spool, SpoolError,
};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
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

fn parts(root: &Path, prompt: PromptDeliveryPlan) -> RunSpecParts {
    RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new("work-1").unwrap(),
            RunId::new("run-1").unwrap(),
            AttemptId::new("attempt-1").unwrap(),
            HostId::new("host-1").unwrap(),
            HostLifetime::Attempt,
            ExecutionBackendId::new("local-direct").unwrap(),
        ),
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
    let prompt = PromptDeliveryPlan::Stdin;
    let mut candidate = parts(root.path(), prompt.clone());
    candidate.protocol_version = 2;
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::UnsupportedProtocol(2)
    );

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.executable = PathBuf::from("/usr/bin/../bin/true");
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::PathNotCanonical("executable")
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

    let mut candidate = parts(root.path(), prompt.clone());
    candidate.environment = vec![("BAD=KEY".into(), "value".into())];
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::EnvironmentKeyInvalid
    );

    let mut candidate = parts(root.path(), prompt);
    candidate.environment = vec![
        ("PATH".into(), "/bin".into()),
        ("PATH".into(), "/usr/bin".into()),
    ];
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::DuplicateEnvironmentKey
    );
}

#[test]
fn run_spec_partial_has_typed_coordinates_and_payload_free_prompt_modes() {
    let root = TempDir::new("typed-coordinates");
    let prompt = PromptDeliveryPlan::ProtectedReference(
        ProtectedPromptReference::new("prompt-slot-1").unwrap(),
    );
    let spec = RunSpec::new(parts(root.path(), prompt)).unwrap();
    assert_eq!(spec.work_id().as_str(), "work-1");
    assert_eq!(spec.run_id().as_str(), "run-1");
    assert_eq!(spec.attempt_id().as_str(), "attempt-1");
    assert_eq!(spec.host_id().as_str(), "host-1");
    assert_eq!(spec.host_lifetime(), HostLifetime::Attempt);
    assert_eq!(spec.backend_id().as_str(), "local-direct");
    assert!(matches!(
        spec.prompt_delivery(),
        PromptDeliveryPlan::ProtectedReference(_)
    ));

    assert_eq!(
        ProtectedPromptReference::new("../prompt").unwrap_err(),
        RunSpecError::FieldInvalid("protected_prompt_reference")
    );
    assert_eq!(
        BackendPromptSession::new("/tmp/session").unwrap_err(),
        RunSpecError::FieldInvalid("backend_prompt_session")
    );
}

#[test]
fn debug_redacts_argv_environment_and_prompt_coordinates() {
    let root = TempDir::new("debug-redaction");
    let mut candidate = parts(
        root.path(),
        PromptDeliveryPlan::BackendSession(BackendPromptSession::new("SESSION_SENTINEL").unwrap()),
    );
    candidate.arguments = vec!["ARG_SENTINEL".into()];
    candidate.environment = vec![("SAFE_KEY".into(), "ENV_SENTINEL".into())];
    let rendered_parts = format!("{candidate:?}");
    let rendered_spec = format!("{:?}", RunSpec::new(candidate).unwrap());
    for rendered in [&rendered_parts, &rendered_spec] {
        assert!(!rendered.contains("ARG_SENTINEL"));
        assert!(!rendered.contains("ENV_SENTINEL"));
        assert!(!rendered.contains("SESSION_SENTINEL"));
    }
}

#[test]
fn path_and_environment_aggregate_bounds_fail_closed() {
    let root = TempDir::new("aggregate-bounds");
    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.executable = PathBuf::from(format!("/{}", "x".repeat(4_096)));
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::FieldInvalid("executable")
    );

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.executable = PathBuf::from(format!("/{}", "x".repeat(4_095)));
    assert_eq!(candidate.executable.as_os_str().as_bytes().len(), 4_096);
    assert!(RunSpec::new(candidate).is_ok());

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.executable = PathBuf::from(OsString::from_vec(b"/bin/\xff".to_vec()));
    assert!(RunSpec::new(candidate).is_ok());

    let mut candidate = parts(root.path(), PromptDeliveryPlan::Stdin);
    candidate.environment = (0..17)
        .map(|index| (format!("KEY_{index}").into(), "x".repeat(4_096).into()))
        .collect();
    assert_eq!(
        RunSpec::new(candidate).unwrap_err(),
        RunSpecError::EnvironmentTooLarge
    );
}

#[test]
fn arbitrary_execution_is_refused_without_descendant_complete_containment() {
    let root = TempDir::new("containment-refusal");
    let spec = RunSpec::new(parts(root.path(), PromptDeliveryPlan::Stdin)).unwrap();
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
