// SPDX-License-Identifier: Elastic-2.0

use automonique_agents::{
    AdapterEnvironment, CancellationToken, CodexAdapter, CodexInvocationPlan, CoordinateError,
    ExecutableInspection, ExecutionMode, NormalizedEvent, ProviderDisposition, RecordedKind,
    ResumeBinding, RunCoordinates, RunRequest, SessionScope, StreamAuthority, normalize_jsonl,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

fn scope(name: &str) -> SessionScope {
    SessionScope::new(name, "codex-account", "codex-cli").expect("scope")
}

fn coordinates(scope: SessionScope) -> RunCoordinates {
    RunCoordinates::new("run-1", "turn-1", scope).expect("coordinates")
}

fn request(scope: SessionScope, mode: ExecutionMode, prompt: &[u8]) -> RunRequest {
    RunRequest::new(
        coordinates(scope),
        mode,
        prompt,
        AdapterEnvironment::empty(),
    )
    .expect("request")
}

fn success_response(final_text: &str) -> Vec<u8> {
    format!(
        concat!(
            "{{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}}\n",
            "{{\"type\":\"turn.started\"}}\n",
            "{{\"type\":\"item.started\",\"item\":{{\"id\":\"message-1\",\"type\":\"agent_message\"}}}}\n",
            "{{\"type\":\"item.updated\",\"item\":{{\"id\":\"message-1\",\"type\":\"agent_message\",\"text\":\"preview fragment\"}}}}\n",
            "{{\"type\":\"item.completed\",\"item\":{{\"id\":\"message-1\",\"type\":\"agent_message\",\"text\":\"{}\"}}}}\n",
            "{{\"type\":\"turn.completed\",\"usage\":{{\"cached_input_tokens\":1,\"input_tokens\":2,\"output_tokens\":3}}}}\n"
        ),
        final_text
    )
    .into_bytes()
}

fn candidate_file(contents: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("candidate");
    fs::write(&path, contents).expect("candidate bytes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).expect("candidate mode");
    (directory, path)
}

#[test]
fn executable_inspection_is_read_only_bounded_and_no_follow() {
    let contents = b"candidate bytes are inspected, never executed";
    let (directory, path) = candidate_file(contents);
    let inspection = ExecutableInspection::inspect(&path).expect("read-only inspection");
    let expected = Sha256::digest(contents)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(inspection.sha256(), expected);
    assert_eq!(inspection.size(), contents.len() as u64);
    assert_eq!(inspection.mode(), 0o500);

    assert_eq!(
        ExecutableInspection::inspect("relative-candidate")
            .expect_err("relative path refused")
            .category(),
        "unsafe_executable"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o520)).expect("unsafe mode");
    assert_eq!(
        ExecutableInspection::inspect(&path)
            .expect_err("group writable refused")
            .category(),
        "unsafe_executable"
    );
    let link = directory.path().join("candidate-link");
    symlink(&path, &link).expect("candidate symlink");
    assert_eq!(
        ExecutableInspection::inspect(link)
            .expect_err("symlink refused")
            .category(),
        "unsafe_executable"
    );
}

#[test]
fn invocation_plan_is_exact_and_redacted() {
    let (_directory, path) = candidate_file(b"metadata only");
    let inspection = ExecutableInspection::inspect(path).expect("inspection");
    let binding = ResumeBinding::new(scope("tenant-a"), "fixture-session").expect("binding");
    let environment = AdapterEnvironment::new([
        ("CODEX_HOME".to_owned(), "/opaque/config".to_owned()),
        ("SSL_CERT_FILE".to_owned(), "/opaque/cert".to_owned()),
    ])
    .expect("allowlisted names");
    let run_request = RunRequest::new(
        coordinates(scope("tenant-a")),
        ExecutionMode::Resume(binding),
        b"secret prompt".as_slice(),
        environment,
    )
    .expect("request");
    let plan = CodexInvocationPlan::new(inspection, &run_request);
    assert_eq!(
        plan.arguments(),
        ["exec", "resume", "fixture-session", "--json", "-"]
    );
    assert_eq!(plan.prompt_bytes(), b"secret prompt".len());
    assert_eq!(plan.environment_keys(), ["CODEX_HOME", "SSL_CERT_FILE"]);
    let debug = format!("{plan:?} {run_request:?}");
    assert!(!debug.contains("secret prompt"));
    assert!(!debug.contains("/opaque/config"));
    assert!(!debug.contains("/opaque/cert"));
}

#[test]
fn open_and_run_are_typed_refusals_and_candidate_has_no_effect() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let marker = directory.path().join("must-not-exist");
    let candidate = directory.path().join("candidate");
    fs::write(
        &candidate,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .expect("candidate script bytes");
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o500)).expect("candidate mode");
    let inspection = ExecutableInspection::inspect(candidate).expect("metadata inspection only");
    let run_request = request(
        scope("tenant-a"),
        ExecutionMode::NewSession,
        b"never delivered",
    );
    let plan = CodexInvocationPlan::new(inspection, &run_request);
    assert_eq!(
        CodexAdapter::open(&plan)
            .err()
            .expect("open cannot construct an adapter")
            .category(),
        "execution_unavailable"
    );
    assert_eq!(
        CodexAdapter::run(&plan, &run_request, &CancellationToken::new())
            .expect_err("run cannot start a process")
            .category(),
        "execution_unavailable"
    );
    assert!(!marker.exists(), "candidate executable was never run");
}

#[test]
fn strict_success_normalization_separates_disposition_from_events() {
    let transcript = normalize_jsonl(
        &coordinates(scope("tenant-a")),
        &ExecutionMode::NewSession,
        &success_response("final answer"),
    )
    .expect("strict fixture normalization");
    assert_eq!(transcript.disposition(), ProviderDisposition::Succeeded);
    assert_eq!(
        transcript.binding().provider_session_id(),
        "fixture-session"
    );
    assert_eq!(
        transcript
            .events()
            .iter()
            .map(NormalizedEvent::sequence)
            .collect::<Vec<_>>(),
        (1..=transcript.events().len() as u64).collect::<Vec<_>>()
    );
    assert_eq!(transcript.events()[2].authority(), StreamAuthority::Preview);
    assert!(transcript.events().iter().any(|event| matches!(
        event,
        NormalizedEvent::Recorded(recorded)
            if recorded.kind() == RecordedKind::AssistantMessageCompleted
                && recorded.text() == Some("final answer")
    )));
    assert_eq!(
        transcript
            .events()
            .iter()
            .filter(|event| matches!(
                event,
                NormalizedEvent::Recorded(recorded)
                    if recorded.kind() == RecordedKind::TurnCompleted
            ))
            .count(),
        1
    );
}

#[test]
fn strict_failure_is_provider_disposition_not_run_terminal() {
    let bytes = concat!(
        "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n",
        "{\"type\":\"turn.started\"}\n",
        "{\"type\":\"turn.failed\",\"error\":{\"message\":\"fixture failure\"}}\n"
    );
    let transcript = normalize_jsonl(
        &coordinates(scope("tenant-a")),
        &ExecutionMode::NewSession,
        bytes.as_bytes(),
    )
    .expect("strict failed fixture");
    assert_eq!(transcript.disposition(), ProviderDisposition::Failed);
    assert!(transcript.events().iter().any(|event| matches!(
        event,
        NormalizedEvent::Recorded(recorded)
            if recorded.kind() == RecordedKind::ProviderFault
                && recorded.text() == Some("fixture failure")
    )));
}

#[test]
fn unknown_duplicate_partial_and_oversize_jsonl_fail_closed() {
    for (bytes, category) in [
        (b"{\"type\":\"future.event\"}\n".to_vec(), "unknown_event"),
        (
            b"{\"type\":\"thread.started\",\"type\":\"thread.started\",\"thread_id\":\"x\"}\n"
                .to_vec(),
            "invalid_json",
        ),
        (
            b"{\"type\":\"thread.started\",\"thread_id\":\"x\"}".to_vec(),
            "invalid_json",
        ),
        (vec![b'x'; 70_000], "invalid_json"),
    ] {
        let error = normalize_jsonl(
            &coordinates(scope("tenant-a")),
            &ExecutionMode::NewSession,
            &bytes,
        )
        .expect_err("fixture refused");
        assert_eq!(error.category(), category);
    }

    let oversized_line = format!(
        "{{\"type\":\"thread.started\",\"thread_id\":\"{}\"}}\n",
        "x".repeat(70_000)
    );
    assert_eq!(
        normalize_jsonl(
            &coordinates(scope("tenant-a")),
            &ExecutionMode::NewSession,
            oversized_line.as_bytes(),
        )
        .expect_err("line ceiling")
        .category(),
        "output_too_large"
    );
}

#[test]
fn item_lifecycle_and_resume_scope_are_exact() {
    let mismatched_item = concat!(
        "{\"type\":\"thread.started\",\"thread_id\":\"fixture-session\"}\n",
        "{\"type\":\"turn.started\"}\n",
        "{\"type\":\"item.started\",\"item\":{\"id\":\"message-1\",\"type\":\"agent_message\"}}\n",
        "{\"type\":\"item.completed\",\"item\":{\"id\":\"message-2\",\"type\":\"agent_message\",\"text\":\"wrong\"}}\n"
    );
    assert_eq!(
        normalize_jsonl(
            &coordinates(scope("tenant-a")),
            &ExecutionMode::NewSession,
            mismatched_item.as_bytes(),
        )
        .expect_err("mismatched item")
        .category(),
        "event_order"
    );

    let binding = ResumeBinding::new(scope("tenant-a"), "fixture-session").expect("binding");
    assert_eq!(
        RunRequest::new(
            coordinates(scope("tenant-b")),
            ExecutionMode::Resume(binding),
            b"prompt".as_slice(),
            AdapterEnvironment::empty(),
        )
        .expect_err("cross-scope resume"),
        CoordinateError::CrossScopeResume
    );
    assert!(matches!(
        ResumeBinding::new(scope("tenant-a"), "--json"),
        Err(CoordinateError::InvalidField("provider_session_id"))
    ));
}
