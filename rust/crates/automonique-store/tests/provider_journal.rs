// SPDX-License-Identifier: Elastic-2.0

//! Provider session journal invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_store::provider_journal::{
    ApprovalDecision, ApprovalRecord, BindingKind, BindingRecord, CursorAdvance, FinishReason,
    PROVIDER_JOURNAL_SCHEMA_VERSION, ProcessExit, ProcessSpawn, ProcessState, ProcessTermination,
    ProviderJournal, RequestDirection, RequestOutcomeCommit, RequestRecord, RequestSettlement,
    RequestState, SessionClosing, SessionClosure, SessionOpening, SessionState, SettledOutcome,
    TurnCompletion, TurnOpening, TurnOutcome, TurnState, TurnUsage,
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

// Lowercase hex with real letters, so `to_uppercase` genuinely changes them.
const EXECUTABLE_DIGEST: &str = "abababababababababababababababababababababababababababababababab";
const PROMPT_DIGEST: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const REPLY_DIGEST: &str = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
const TOOL_DIGEST: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
const SCHEMA_DIGEST: &str = "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b";
const CAPABILITY_DIGEST: &str = "2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";

struct PrivateJournal {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateJournal {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("provider-journal.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn journal() -> (PrivateJournal, ProviderJournal) {
    let private = PrivateJournal::new();
    let opened = ProviderJournal::open(private.path()).expect("open journal");
    (private, opened)
}

fn spawn(journal: &mut ProviderJournal, spawn_key: &str, attempt_id: &str) -> i64 {
    journal
        .record_process(ProcessSpawn {
            spawn_key,
            attempt_id,
            provider_kind: "codex",
            executable_digest: EXECUTABLE_DIGEST,
            spawned_ms: 10,
        })
        .expect("record process")
        .process_id
}

fn open_session(journal: &mut ProviderJournal, process_id: i64, key: &str) -> i64 {
    journal
        .open_session(SessionOpening {
            process_id,
            provider_session_key: key,
            opened_ms: 20,
        })
        .expect("open session")
        .session_id
}

fn open_turn(journal: &mut ProviderJournal, session_id: i64, ordinal: u64, key: &str) -> i64 {
    journal
        .open_turn(TurnOpening {
            session_id,
            ordinal,
            turn_key: key,
            opened_ms: 30,
        })
        .expect("open turn")
        .turn_id
}

fn record_request(journal: &mut ProviderJournal, turn_id: i64, key: &str, digest: &str) -> i64 {
    journal
        .record_request(RequestRecord {
            turn_id,
            request_key: key,
            direction: RequestDirection::ToProvider,
            payload_digest: digest,
            created_ms: 40,
        })
        .expect("record request")
        .request_id
}

fn answered<'a>(request_key: &'a str, response_digest: &'a str) -> RequestSettlement<'a> {
    RequestSettlement {
        request_key,
        expected_revision: 1,
        outcome: SettledOutcome::Answered { response_digest },
    }
}

/// A live process with an open session and an open first turn.
fn live_turn(journal: &mut ProviderJournal) -> (i64, i64, i64) {
    let process_id = spawn(journal, "spawn:a", "attempt:a");
    let session_id = open_session(journal, process_id, "provider-session-a");
    let turn_id = open_turn(journal, session_id, 1, "turn:1");
    (process_id, session_id, turn_id)
}

#[test]
fn open_requires_private_owned_paths_and_refuses_foreign_schema() {
    let private = PrivateJournal::new();
    let journal = ProviderJournal::open(private.path()).expect("open private journal");
    assert_eq!(journal.path(), private.path());
    drop(journal);

    let connection = Connection::open(private.path()).expect("raw reopen");
    connection
        .pragma_update(None, "user_version", PROVIDER_JOURNAL_SCHEMA_VERSION + 1)
        .expect("change version");
    drop(connection);
    let error = ProviderJournal::open(private.path()).expect_err("version refusal");
    assert_eq!(error.category(), "schema_version");

    let public = tempfile::tempdir().expect("public temporary directory");
    fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755))
        .expect("public permissions");
    let error =
        ProviderJournal::open(public.path().join("journal.sqlite3")).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn full_lifecycle_recovers_byte_exact_bindings() {
    let (private, mut journal) = journal();
    let process_id = spawn(&mut journal, "spawn:a", "attempt:a");
    let session_id = open_session(&mut journal, process_id, "provider-session-a");

    journal
        .bind_capability(BindingRecord {
            session_id,
            name: "approval-channel",
            version: "2",
            value_digest: CAPABILITY_DIGEST,
            bound_ms: 21,
        })
        .expect("bind capability");
    journal
        .bind_schema(BindingRecord {
            session_id,
            name: "event-envelope",
            version: "v1.4.0",
            value_digest: SCHEMA_DIGEST,
            bound_ms: 22,
        })
        .expect("bind schema");
    journal
        .record_approval(ApprovalRecord {
            session_id,
            approval_key: "exec:git-push",
            decision: ApprovalDecision::Granted,
            deciding_actor: "operator:ben",
            decided_ms: 23,
        })
        .expect("record approval");

    // Turn one completes, settling its request and advancing the cursor.
    let first_turn = open_turn(&mut journal, session_id, 1, "turn:1");
    record_request(&mut journal, first_turn, "req:prompt-1", PROMPT_DIGEST);
    let completed = journal
        .complete_turn(TurnCompletion {
            turn_id: first_turn,
            expected_revision: 1,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[answered("req:prompt-1", REPLY_DIGEST)],
            cursor: Some(CursorAdvance {
                session_id,
                stream: "events",
                sequence: 17,
                now_ms: 50,
            }),
            usage: None,
        })
        .expect("complete first turn");
    assert_eq!(completed.ordinal, 1);
    assert_eq!(completed.revision, 2);
    assert!(!completed.duplicate);

    // Turn two stays open with one unanswered request: the recovery case.
    let second_turn = open_turn(&mut journal, session_id, 2, "turn:2");
    record_request(&mut journal, second_turn, "req:prompt-2", PROMPT_DIGEST);
    record_request(&mut journal, second_turn, "req:tool-1", TOOL_DIGEST);
    journal
        .settle_request(RequestOutcomeCommit {
            turn_id: second_turn,
            now_ms: 60,
            settlement: answered("req:prompt-2", REPLY_DIGEST),
        })
        .expect("settle one request");

    // A restarting supervisor reads one point-in-time view.
    drop(journal);
    let mut reopened = ProviderJournal::open(private.path()).expect("reopen journal");
    let recovery = reopened.recover_attempt("attempt:a").expect("recover");

    let process = recovery.process.expect("live process");
    assert_eq!(process.process_id, process_id);
    assert_eq!(process.state, ProcessState::Live);
    assert_eq!(process.executable_digest, EXECUTABLE_DIGEST);
    assert_eq!(process.provider_kind, "codex");
    assert_eq!(process.exited_ms, None);

    let session = recovery.session.expect("open session");
    assert_eq!(session.session_id, session_id);
    assert_eq!(session.state, SessionState::Open);
    assert_eq!(session.provider_session_key, "provider-session-a");

    let turn = recovery.turn.expect("open turn");
    assert_eq!(turn.turn_id, second_turn);
    assert_eq!(turn.ordinal, 2);
    assert_eq!(turn.state, TurnState::Open);

    assert_eq!(recovery.pending_requests.len(), 1);
    let pending = &recovery.pending_requests[0];
    assert_eq!(pending.request_key, "req:tool-1");
    assert_eq!(pending.payload_digest, TOOL_DIGEST);
    assert_eq!(pending.outcome, RequestState::Pending);
    assert_eq!(pending.response_digest, None);
    assert_eq!(pending.direction, RequestDirection::ToProvider);

    assert_eq!(recovery.cursors.len(), 1);
    assert_eq!(recovery.cursors[0].stream, "events");
    assert_eq!(recovery.cursors[0].sequence, 17);

    assert_eq!(recovery.capabilities.len(), 1);
    assert_eq!(recovery.capabilities[0].name, "approval-channel");
    assert_eq!(recovery.capabilities[0].version, "2");
    assert_eq!(recovery.capabilities[0].value_digest, CAPABILITY_DIGEST);

    assert_eq!(recovery.schemas.len(), 1);
    assert_eq!(recovery.schemas[0].version, "v1.4.0");
    assert_eq!(recovery.schemas[0].value_digest, SCHEMA_DIGEST);

    assert_eq!(recovery.approvals.len(), 1);
    assert_eq!(recovery.approvals[0].approval_key, "exec:git-push");
    assert_eq!(recovery.approvals[0].decision, ApprovalDecision::Granted);
    assert_eq!(recovery.approvals[0].deciding_actor, "operator:ben");

    // The settled first turn kept its exact answer digest.
    let first = reopened
        .turn_requests(first_turn)
        .expect("first turn requests");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].outcome, RequestState::Answered);
    assert_eq!(first[0].response_digest.as_deref(), Some(REPLY_DIGEST));
    assert_eq!(first[0].settled_ms, Some(50));
    assert_eq!(first[0].revision, 2);

    let turns = reopened.session_turns(session_id).expect("session turns");
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0].state, TurnState::Completed);
    assert_eq!(turns[1].state, TurnState::Open);
}

#[test]
fn second_live_process_for_one_attempt_refuses() {
    let (_private, mut journal) = journal();
    let first = spawn(&mut journal, "spawn:a", "attempt:a");
    let error = journal
        .record_process(ProcessSpawn {
            spawn_key: "spawn:b",
            attempt_id: "attempt:a",
            provider_kind: "claude",
            executable_digest: EXECUTABLE_DIGEST,
            spawned_ms: 11,
        })
        .expect_err("second live process refusal");
    assert_eq!(error.category(), "process_live");
    assert!(error.to_string().contains(&first.to_string()));

    // The refusal is scoped to the attempt, not to the provider.
    let other = spawn(&mut journal, "spawn:c", "attempt:b");
    assert_ne!(other, first);

    // After a terminal observation the attempt may be respawned.
    journal
        .finish_process(ProcessExit {
            process_id: first,
            expected_revision: 1,
            now_ms: 70,
            termination: ProcessTermination::Exited,
        })
        .expect("finish first process");
    let replacement = spawn(&mut journal, "spawn:d", "attempt:a");
    assert_ne!(replacement, first);
}

#[test]
fn second_open_session_for_one_process_refuses() {
    let (_private, mut journal) = journal();
    let process_id = spawn(&mut journal, "spawn:a", "attempt:a");
    let first = open_session(&mut journal, process_id, "provider-session-a");
    let error = journal
        .open_session(SessionOpening {
            process_id,
            provider_session_key: "provider-session-b",
            opened_ms: 21,
        })
        .expect_err("second open session refusal");
    assert_eq!(error.category(), "session_open");

    journal
        .close_session(SessionClosing {
            session_id: first,
            expected_revision: 1,
            now_ms: 80,
            closure: SessionClosure::Closed,
        })
        .expect("close first session");
    let second = open_session(&mut journal, process_id, "provider-session-b");
    assert_ne!(second, first);
    assert_eq!(
        journal.session(first).expect("first session").state,
        SessionState::Closed
    );
}

#[test]
fn second_open_turn_for_one_session_refuses() {
    let (_private, mut journal) = journal();
    let (_process_id, session_id, first) = live_turn(&mut journal);
    let error = journal
        .open_turn(TurnOpening {
            session_id,
            ordinal: 2,
            turn_key: "turn:2",
            opened_ms: 31,
        })
        .expect_err("second open turn refusal");
    assert_eq!(error.category(), "turn_open");
    assert!(error.to_string().contains(&first.to_string()));
}

#[test]
fn non_contiguous_turn_ordinal_refuses() {
    let (_private, mut journal) = journal();
    let (_process_id, session_id, first) = live_turn(&mut journal);
    journal
        .complete_turn(TurnCompletion {
            turn_id: first,
            expected_revision: 1,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[],
            cursor: None,
            usage: None,
        })
        .expect("complete first turn");

    let error = journal
        .open_turn(TurnOpening {
            session_id,
            ordinal: 3,
            turn_key: "turn:3",
            opened_ms: 51,
        })
        .expect_err("ordinal gap refusal");
    assert_eq!(error.category(), "turn_ordinal");
    assert!(error.to_string().contains("expected 2"));

    let error = journal
        .open_turn(TurnOpening {
            session_id,
            ordinal: 1,
            turn_key: "turn:repeat",
            opened_ms: 51,
        })
        .expect_err("ordinal reuse refusal");
    assert_eq!(error.category(), "turn_ordinal");

    // The exact next ordinal is accepted.
    let second = open_turn(&mut journal, session_id, 2, "turn:2");
    assert_eq!(
        journal.turn(second).expect("second turn").ordinal,
        2,
        "contiguous ordinal must land"
    );
}

#[test]
fn duplicate_request_key_in_one_turn_refuses() {
    let (_private, mut journal) = journal();
    let (_process_id, _session_id, turn_id) = live_turn(&mut journal);
    record_request(&mut journal, turn_id, "req:prompt", PROMPT_DIGEST);

    let error = journal
        .record_request(RequestRecord {
            turn_id,
            request_key: "req:prompt",
            direction: RequestDirection::ToProvider,
            payload_digest: TOOL_DIGEST,
            created_ms: 40,
        })
        .expect_err("digest conflict refusal");
    assert_eq!(error.category(), "idempotency_conflict");

    let error = journal
        .record_request(RequestRecord {
            turn_id,
            request_key: "req:prompt",
            direction: RequestDirection::FromProvider,
            payload_digest: PROMPT_DIGEST,
            created_ms: 40,
        })
        .expect_err("direction conflict refusal");
    assert_eq!(error.category(), "idempotency_conflict");

    assert_eq!(
        journal.turn_requests(turn_id).expect("turn requests").len(),
        1
    );
}

#[test]
fn cursor_moving_backward_refuses() {
    let (_private, mut journal) = journal();
    let (_process_id, session_id, _turn_id) = live_turn(&mut journal);
    let receipt = journal
        .advance_cursor(CursorAdvance {
            session_id,
            stream: "events",
            sequence: 12,
            now_ms: 41,
        })
        .expect("first advance");
    assert_eq!(receipt.revision, 1);

    let receipt = journal
        .advance_cursor(CursorAdvance {
            session_id,
            stream: "events",
            sequence: 30,
            now_ms: 42,
        })
        .expect("forward advance");
    assert_eq!(receipt.revision, 2);

    let error = journal
        .advance_cursor(CursorAdvance {
            session_id,
            stream: "events",
            sequence: 29,
            now_ms: 43,
        })
        .expect_err("cursor regression refusal");
    assert_eq!(error.category(), "cursor_regression");
    assert!(error.to_string().contains("durable sequence 30"));

    let cursors = journal.cursors(session_id).expect("cursors");
    assert_eq!(cursors.len(), 1);
    assert_eq!(cursors[0].sequence, 30);
    assert_eq!(cursors[0].updated_ms, 42);

    // A different stream keeps its own sequence.
    journal
        .advance_cursor(CursorAdvance {
            session_id,
            stream: "notifications",
            sequence: 1,
            now_ms: 44,
        })
        .expect("independent stream");
    assert_eq!(journal.cursors(session_id).expect("cursors").len(), 2);
}

#[test]
fn rebinding_a_capability_to_a_different_value_refuses() {
    let (_private, mut journal) = journal();
    let process_id = spawn(&mut journal, "spawn:a", "attempt:a");
    let session_id = open_session(&mut journal, process_id, "provider-session-a");
    journal
        .bind_capability(BindingRecord {
            session_id,
            name: "approval-channel",
            version: "2",
            value_digest: CAPABILITY_DIGEST,
            bound_ms: 21,
        })
        .expect("first capability binding");

    let error = journal
        .bind_capability(BindingRecord {
            session_id,
            name: "approval-channel",
            version: "2",
            value_digest: SCHEMA_DIGEST,
            bound_ms: 22,
        })
        .expect_err("digest rebinding refusal");
    assert_eq!(error.category(), "binding_conflict");
    assert!(error.to_string().contains("capability_binding"));

    let error = journal
        .bind_capability(BindingRecord {
            session_id,
            name: "approval-channel",
            version: "3",
            value_digest: CAPABILITY_DIGEST,
            bound_ms: 22,
        })
        .expect_err("version rebinding refusal");
    assert_eq!(error.category(), "binding_conflict");

    // Schema bindings live in their own namespace and do not collide.
    journal
        .bind_schema(BindingRecord {
            session_id,
            name: "approval-channel",
            version: "2",
            value_digest: SCHEMA_DIGEST,
            bound_ms: 23,
        })
        .expect("schema namespace is separate");

    let capabilities = journal
        .bindings(session_id, BindingKind::Capability)
        .expect("capabilities");
    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].value_digest, CAPABILITY_DIGEST);
    assert_eq!(capabilities[0].version, "2");
}

#[test]
fn double_deciding_an_approval_differently_refuses() {
    let (_private, mut journal) = journal();
    let process_id = spawn(&mut journal, "spawn:a", "attempt:a");
    let session_id = open_session(&mut journal, process_id, "provider-session-a");
    journal
        .record_approval(ApprovalRecord {
            session_id,
            approval_key: "exec:git-push",
            decision: ApprovalDecision::Granted,
            deciding_actor: "operator:ben",
            decided_ms: 23,
        })
        .expect("first decision");

    let error = journal
        .record_approval(ApprovalRecord {
            session_id,
            approval_key: "exec:git-push",
            decision: ApprovalDecision::Denied,
            deciding_actor: "operator:ben",
            decided_ms: 23,
        })
        .expect_err("reversal refusal");
    assert_eq!(error.category(), "binding_conflict");

    let error = journal
        .record_approval(ApprovalRecord {
            session_id,
            approval_key: "exec:git-push",
            decision: ApprovalDecision::Granted,
            deciding_actor: "operator:someone-else",
            decided_ms: 23,
        })
        .expect_err("actor rewrite refusal");
    assert_eq!(error.category(), "binding_conflict");

    let approvals = journal.approvals(session_id).expect("approvals");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].decision, ApprovalDecision::Granted);
    assert_eq!(approvals[0].deciding_actor, "operator:ben");
}

#[test]
fn exact_replay_writes_are_idempotent_without_duplication() {
    let (_private, mut journal) = journal();
    let first = journal
        .record_process(ProcessSpawn {
            spawn_key: "spawn:a",
            attempt_id: "attempt:a",
            provider_kind: "codex",
            executable_digest: EXECUTABLE_DIGEST,
            spawned_ms: 10,
        })
        .expect("first spawn");
    let replay = journal
        .record_process(ProcessSpawn {
            spawn_key: "spawn:a",
            attempt_id: "attempt:a",
            provider_kind: "codex",
            executable_digest: EXECUTABLE_DIGEST,
            spawned_ms: 10,
        })
        .expect("replayed spawn");
    assert_eq!(replay.process_id, first.process_id);
    assert!(replay.duplicate);
    assert!(!first.duplicate);

    let conflict = journal
        .record_process(ProcessSpawn {
            spawn_key: "spawn:a",
            attempt_id: "attempt:a",
            provider_kind: "codex",
            executable_digest: PROMPT_DIGEST,
            spawned_ms: 10,
        })
        .expect_err("different executable refusal");
    assert_eq!(conflict.category(), "idempotency_conflict");

    let session = journal
        .open_session(SessionOpening {
            process_id: first.process_id,
            provider_session_key: "provider-session-a",
            opened_ms: 20,
        })
        .expect("open session");
    let replay = journal
        .open_session(SessionOpening {
            process_id: first.process_id,
            provider_session_key: "provider-session-a",
            opened_ms: 20,
        })
        .expect("replayed session");
    assert_eq!(replay.session_id, session.session_id);
    assert!(replay.duplicate);

    let turn = journal
        .open_turn(TurnOpening {
            session_id: session.session_id,
            ordinal: 1,
            turn_key: "turn:1",
            opened_ms: 30,
        })
        .expect("open turn");
    let replay = journal
        .open_turn(TurnOpening {
            session_id: session.session_id,
            ordinal: 1,
            turn_key: "turn:1",
            opened_ms: 30,
        })
        .expect("replayed turn");
    assert_eq!(replay.turn_id, turn.turn_id);
    assert!(replay.duplicate);

    let request = record_request(&mut journal, turn.turn_id, "req:prompt", PROMPT_DIGEST);
    let replay = journal
        .record_request(RequestRecord {
            turn_id: turn.turn_id,
            request_key: "req:prompt",
            direction: RequestDirection::ToProvider,
            payload_digest: PROMPT_DIGEST,
            created_ms: 40,
        })
        .expect("replayed request");
    assert_eq!(replay.request_id, request);
    assert!(replay.duplicate);

    journal
        .bind_capability(BindingRecord {
            session_id: session.session_id,
            name: "approval-channel",
            version: "2",
            value_digest: CAPABILITY_DIGEST,
            bound_ms: 21,
        })
        .expect("bind capability");
    let replay = journal
        .bind_capability(BindingRecord {
            session_id: session.session_id,
            name: "approval-channel",
            version: "2",
            value_digest: CAPABILITY_DIGEST,
            bound_ms: 21,
        })
        .expect("replayed capability");
    assert!(replay.duplicate);

    journal
        .record_approval(ApprovalRecord {
            session_id: session.session_id,
            approval_key: "exec:git-push",
            decision: ApprovalDecision::Granted,
            deciding_actor: "operator:ben",
            decided_ms: 23,
        })
        .expect("record approval");
    let replay = journal
        .record_approval(ApprovalRecord {
            session_id: session.session_id,
            approval_key: "exec:git-push",
            decision: ApprovalDecision::Granted,
            deciding_actor: "operator:ben",
            decided_ms: 23,
        })
        .expect("replayed approval");
    assert!(replay.duplicate);

    let settlement = answered("req:prompt", REPLY_DIGEST);
    let completion = journal
        .complete_turn(TurnCompletion {
            turn_id: turn.turn_id,
            expected_revision: 1,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[settlement],
            cursor: Some(CursorAdvance {
                session_id: session.session_id,
                stream: "events",
                sequence: 9,
                now_ms: 50,
            }),
            usage: None,
        })
        .expect("complete turn");
    let replay = journal
        .complete_turn(TurnCompletion {
            turn_id: turn.turn_id,
            expected_revision: 1,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[settlement],
            cursor: Some(CursorAdvance {
                session_id: session.session_id,
                stream: "events",
                sequence: 9,
                now_ms: 50,
            }),
            usage: None,
        })
        .expect("replayed completion");
    assert!(replay.duplicate);
    assert_eq!(replay.revision, completion.revision);

    // Nothing duplicated anywhere.
    let raw = Connection::open(journal.path()).expect("raw inspect");
    for (table, expected) in [
        ("provider_processes", 1_i64),
        ("provider_sessions", 1),
        ("provider_turns", 1),
        ("provider_turn_usage", 0),
        ("provider_requests", 1),
        ("provider_cursors", 1),
        ("provider_bindings", 1),
        ("provider_approvals", 1),
    ] {
        let count: i64 = raw
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count rows");
        assert_eq!(count, expected, "{table} must hold exactly one row");
    }
}

#[test]
fn completed_turn_usage_is_atomic_durable_and_aggregated() {
    let (_private, mut journal) = journal();
    let (_process_id, _session_id, turn_id) = live_turn(&mut journal);
    let usage = TurnUsage {
        gen_ai_system: "openai",
        request_model: Some("gpt-5"),
        response_model: Some("gpt-5.1"),
        input_tokens: 13,
        cached_input_tokens: 5,
        output_tokens: 8,
        finish_reason: FinishReason::Stop,
    };
    let completion = TurnCompletion {
        turn_id,
        expected_revision: 1,
        now_ms: 50,
        outcome: TurnOutcome::Completed,
        settlements: &[],
        cursor: None,
        usage: Some(usage),
    };
    journal
        .complete_turn(completion)
        .expect("complete with usage");

    let recorded = journal
        .turn_usage(turn_id)
        .expect("usage read")
        .expect("usage row");
    assert_eq!(recorded.gen_ai_system, "openai");
    assert_eq!(recorded.request_model.as_deref(), Some("gpt-5"));
    assert_eq!(recorded.response_model.as_deref(), Some("gpt-5.1"));
    assert_eq!(recorded.input_tokens, 13);
    assert_eq!(recorded.cached_input_tokens, 5);
    assert_eq!(recorded.output_tokens, 8);
    assert_eq!(recorded.finish_reason, FinishReason::Stop);
    assert_eq!(
        journal.usage_totals().expect("usage totals"),
        automonique_store::provider_journal::UsageTotals {
            requests: 1,
            input_tokens: 13,
            output_tokens: 8,
        }
    );

    let replay = journal
        .complete_turn(TurnCompletion {
            expected_revision: 1,
            ..completion
        })
        .expect("exact replay");
    assert!(replay.duplicate);
    let conflict = journal
        .complete_turn(TurnCompletion {
            usage: Some(TurnUsage {
                output_tokens: 9,
                ..usage
            }),
            ..completion
        })
        .expect_err("changed usage refusal");
    assert_eq!(conflict.category(), "already_settled");
}

#[test]
fn a_v1_journal_migrates_to_the_usage_schema() {
    let (private, journal) = journal();
    drop(journal);
    let raw = Connection::open(private.path()).expect("raw v1 simulation");
    raw.execute("DROP TABLE provider_turn_usage", [])
        .expect("remove v2 table");
    raw.pragma_update(None, "user_version", 1).expect("mark v1");
    drop(raw);

    let reopened = ProviderJournal::open(private.path()).expect("migrate v1");
    assert_eq!(reopened.usage_totals().expect("empty totals").requests, 0);
    let raw = Connection::open(private.path()).expect("inspect migrated version");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user version");
    assert_eq!(version, PROVIDER_JOURNAL_SCHEMA_VERSION);
}

#[test]
fn stale_request_revision_refuses_and_settled_requests_do_not_flip() {
    let (_private, mut journal) = journal();
    let (_process_id, _session_id, turn_id) = live_turn(&mut journal);
    record_request(&mut journal, turn_id, "req:prompt", PROMPT_DIGEST);

    let error = journal
        .settle_request(RequestOutcomeCommit {
            turn_id,
            now_ms: 60,
            settlement: RequestSettlement {
                request_key: "req:prompt",
                expected_revision: 2,
                outcome: SettledOutcome::Answered {
                    response_digest: REPLY_DIGEST,
                },
            },
        })
        .expect_err("stale revision refusal");
    assert_eq!(error.category(), "revision_mismatch");
    assert!(error.to_string().contains("durable revision is 1"));
    assert_eq!(
        journal.turn_requests(turn_id).expect("requests")[0].outcome,
        RequestState::Pending
    );

    journal
        .settle_request(RequestOutcomeCommit {
            turn_id,
            now_ms: 60,
            settlement: answered("req:prompt", REPLY_DIGEST),
        })
        .expect("settle pending request");

    // Exact replay is idempotent; a different answer is refused.
    let replay = journal
        .settle_request(RequestOutcomeCommit {
            turn_id,
            now_ms: 61,
            settlement: answered("req:prompt", REPLY_DIGEST),
        })
        .expect("replayed settlement");
    assert!(replay.duplicate);
    let error = journal
        .settle_request(RequestOutcomeCommit {
            turn_id,
            now_ms: 61,
            settlement: answered("req:prompt", TOOL_DIGEST),
        })
        .expect_err("different answer refusal");
    assert_eq!(error.category(), "already_settled");

    let request = &journal.turn_requests(turn_id).expect("requests")[0];
    assert_eq!(request.response_digest.as_deref(), Some(REPLY_DIGEST));
    assert_eq!(request.settled_ms, Some(60));
    assert_eq!(request.revision, 2);
}

#[test]
fn stale_turn_revision_refuses_completion() {
    let (_private, mut journal) = journal();
    let (_process_id, _session_id, turn_id) = live_turn(&mut journal);
    let error = journal
        .complete_turn(TurnCompletion {
            turn_id,
            expected_revision: 7,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[],
            cursor: None,
            usage: None,
        })
        .expect_err("stale turn revision refusal");
    assert_eq!(error.category(), "revision_mismatch");
    assert_eq!(
        journal.turn(turn_id).expect("turn").state,
        TurnState::Open,
        "a refused completion must leave the turn open"
    );
}

#[test]
fn a_refused_last_settlement_discards_the_whole_turn_commit() {
    let (_private, mut journal) = journal();
    let (_process_id, session_id, turn_id) = live_turn(&mut journal);
    record_request(&mut journal, turn_id, "req:one", PROMPT_DIGEST);
    record_request(&mut journal, turn_id, "req:two", TOOL_DIGEST);
    journal
        .advance_cursor(CursorAdvance {
            session_id,
            stream: "events",
            sequence: 5,
            now_ms: 41,
        })
        .expect("initial cursor");

    // The third settlement names a request that does not exist.
    let error = journal
        .complete_turn(TurnCompletion {
            turn_id,
            expected_revision: 1,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[
                answered("req:one", REPLY_DIGEST),
                answered("req:two", REPLY_DIGEST),
                answered("req:missing", REPLY_DIGEST),
            ],
            cursor: Some(CursorAdvance {
                session_id,
                stream: "events",
                sequence: 99,
                now_ms: 50,
            }),
            usage: None,
        })
        .expect_err("unknown request refusal");
    assert_eq!(error.category(), "not_found");

    // Nothing from the refused commit landed: not the earlier settlements,
    // not the cursor, not the turn transition.
    let requests = journal.turn_requests(turn_id).expect("requests");
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(
            request.outcome,
            RequestState::Pending,
            "{} must not have settled",
            request.request_key
        );
        assert_eq!(request.revision, 1);
        assert_eq!(request.settled_ms, None);
    }
    let cursors = journal.cursors(session_id).expect("cursors");
    assert_eq!(cursors[0].sequence, 5);
    assert_eq!(cursors[0].revision, 1);
    let turn = journal.turn(turn_id).expect("turn");
    assert_eq!(turn.state, TurnState::Open);
    assert_eq!(turn.revision, 1);
}

#[test]
fn a_refused_cursor_step_discards_the_whole_turn_commit() {
    let (_private, mut journal) = journal();
    let (_process_id, session_id, turn_id) = live_turn(&mut journal);
    record_request(&mut journal, turn_id, "req:one", PROMPT_DIGEST);
    journal
        .advance_cursor(CursorAdvance {
            session_id,
            stream: "events",
            sequence: 40,
            now_ms: 41,
        })
        .expect("initial cursor");

    let error = journal
        .complete_turn(TurnCompletion {
            turn_id,
            expected_revision: 1,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[answered("req:one", REPLY_DIGEST)],
            cursor: Some(CursorAdvance {
                session_id,
                stream: "events",
                sequence: 39,
                now_ms: 50,
            }),
            usage: None,
        })
        .expect_err("cursor regression refusal");
    assert_eq!(error.category(), "cursor_regression");

    assert_eq!(
        journal.turn_requests(turn_id).expect("requests")[0].outcome,
        RequestState::Pending,
        "a settlement before the refused cursor must not survive"
    );
    assert_eq!(
        journal.cursors(session_id).expect("cursors")[0].sequence,
        40
    );
    assert_eq!(journal.turn(turn_id).expect("turn").state, TurnState::Open);
}

#[test]
fn losing_a_process_cascades_session_and_turn_in_one_transaction() {
    let (_private, mut journal) = journal();
    let (process_id, session_id, turn_id) = live_turn(&mut journal);

    // An orderly exit cannot be recorded while a session is still open.
    let error = journal
        .finish_process(ProcessExit {
            process_id,
            expected_revision: 1,
            now_ms: 70,
            termination: ProcessTermination::Exited,
        })
        .expect_err("open session refusal");
    assert_eq!(error.category(), "session_open");
    assert_eq!(
        journal.process(process_id).expect("process").state,
        ProcessState::Live,
        "a refused exit must not move the process"
    );

    journal
        .finish_process(ProcessExit {
            process_id,
            expected_revision: 1,
            now_ms: 70,
            termination: ProcessTermination::Lost,
        })
        .expect("lose process");

    let process = journal.process(process_id).expect("process");
    assert_eq!(process.state, ProcessState::Lost);
    assert_eq!(process.exited_ms, Some(70));
    assert_eq!(process.revision, 2);
    let session = journal.session(session_id).expect("session");
    assert_eq!(session.state, SessionState::Lost);
    assert_eq!(session.closed_ms, Some(70));
    assert_eq!(session.revision, 2);
    let turn = journal.turn(turn_id).expect("turn");
    assert_eq!(turn.state, TurnState::Aborted);
    assert_eq!(turn.closed_ms, Some(70));
    assert_eq!(turn.revision, 2);

    // A lost process refuses further session and turn work.
    let error = journal
        .open_session(SessionOpening {
            process_id,
            provider_session_key: "provider-session-b",
            opened_ms: 71,
        })
        .expect_err("dead process refusal");
    assert_eq!(error.category(), "not_open");
    let error = journal
        .advance_cursor(CursorAdvance {
            session_id,
            stream: "events",
            sequence: 1,
            now_ms: 72,
        })
        .expect_err("dead session refusal");
    assert_eq!(error.category(), "not_open");

    // Recovery still reports the wreckage rather than an empty answer.
    let recovery = journal.recover_attempt("attempt:a").expect("recover");
    assert_eq!(recovery.process.expect("process").state, ProcessState::Lost);
    assert_eq!(recovery.session.expect("session").state, SessionState::Lost);
    assert_eq!(recovery.turn.expect("turn").state, TurnState::Aborted);
}

#[test]
fn closing_a_session_with_an_open_turn_refuses_but_losing_it_aborts_the_turn() {
    let (_private, mut journal) = journal();
    let (_process_id, session_id, turn_id) = live_turn(&mut journal);
    let error = journal
        .close_session(SessionClosing {
            session_id,
            expected_revision: 1,
            now_ms: 80,
            closure: SessionClosure::Closed,
        })
        .expect_err("open turn refusal");
    assert_eq!(error.category(), "turn_open");
    assert_eq!(
        journal.session(session_id).expect("session").state,
        SessionState::Open
    );

    journal
        .close_session(SessionClosing {
            session_id,
            expected_revision: 1,
            now_ms: 80,
            closure: SessionClosure::Lost,
        })
        .expect("lose session");
    assert_eq!(
        journal.turn(turn_id).expect("turn").state,
        TurnState::Aborted
    );
}

#[test]
fn recovery_of_an_unknown_attempt_is_empty_not_an_error() {
    let (_private, mut journal) = journal();
    spawn(&mut journal, "spawn:a", "attempt:a");
    let recovery = journal.recover_attempt("attempt:none").expect("recover");
    assert!(recovery.process.is_none());
    assert!(recovery.session.is_none());
    assert!(recovery.turn.is_none());
    assert!(recovery.pending_requests.is_empty());
    assert!(recovery.cursors.is_empty());
    assert!(recovery.approvals.is_empty());
    assert_eq!(recovery.attempt_id, "attempt:none");
}

#[test]
fn malformed_caller_fields_refuse_before_touching_the_database() {
    let (_private, mut journal) = journal();
    let process_id = spawn(&mut journal, "spawn:a", "attempt:a");

    // Uppercase hex is not the canonical digest spelling.
    let error = journal
        .record_process(ProcessSpawn {
            spawn_key: "spawn:b",
            attempt_id: "attempt:b",
            provider_kind: "codex",
            executable_digest: &EXECUTABLE_DIGEST.to_uppercase(),
            spawned_ms: 10,
        })
        .expect_err("uppercase digest refusal");
    assert_eq!(error.category(), "invalid_field");

    let error = journal
        .record_process(ProcessSpawn {
            spawn_key: "spawn:b",
            attempt_id: "attempt:b",
            provider_kind: "codex",
            executable_digest: "abcd",
            spawned_ms: 10,
        })
        .expect_err("short digest refusal");
    assert_eq!(error.category(), "invalid_field");

    let error = journal
        .open_session(SessionOpening {
            process_id,
            provider_session_key: &"s".repeat(257),
            opened_ms: 20,
        })
        .expect_err("over-long key refusal");
    assert_eq!(error.category(), "invalid_field");

    let error = journal
        .open_session(SessionOpening {
            process_id,
            provider_session_key: "control\u{7}character",
            opened_ms: 20,
        })
        .expect_err("control character refusal");
    assert_eq!(error.category(), "invalid_field");

    let error = journal
        .open_session(SessionOpening {
            process_id,
            provider_session_key: "provider-session-a",
            opened_ms: -1,
        })
        .expect_err("negative time refusal");
    assert_eq!(error.category(), "invalid_field");

    let raw = Connection::open(journal.path()).expect("raw inspect");
    let sessions: i64 = raw
        .query_row("SELECT count(*) FROM provider_sessions", [], |row| {
            row.get(0)
        })
        .expect("count sessions");
    assert_eq!(sessions, 0, "no refused write may have landed");
}

#[test]
fn a_hand_written_turn_ordinal_gap_surfaces_as_corruption() {
    let (private, mut journal) = journal();
    let (_process_id, session_id, turn_id) = live_turn(&mut journal);
    journal
        .complete_turn(TurnCompletion {
            turn_id,
            expected_revision: 1,
            now_ms: 50,
            outcome: TurnOutcome::Completed,
            settlements: &[],
            cursor: None,
            usage: None,
        })
        .expect("complete first turn");
    drop(journal);

    // Write a turn the API would have refused: ordinal 7 after ordinal 1.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO provider_turns
         (session_id, ordinal, turn_key, state, opened_ms, closed_ms, revision)
         VALUES (?1, 7, 'turn:smuggled', 'open', 60, NULL, 1)",
        params![session_id],
    )
    .expect("smuggle turn row");
    drop(raw);

    let mut reopened = ProviderJournal::open(private.path()).expect("reopen");
    let error = reopened
        .session_turns(session_id)
        .expect_err("contiguity refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("turn_ordinal_contiguity"));

    // Recovery refuses too: it never reports a view built from bad rows.
    let error = reopened
        .recover_attempt("attempt:a")
        .expect_err("recovery refusal");
    assert_eq!(error.category(), "corrupt");
}

#[test]
fn a_hand_written_non_canonical_digest_surfaces_as_corruption() {
    let (private, mut journal) = journal();
    let (_process_id, _session_id, turn_id) = live_turn(&mut journal);
    record_request(&mut journal, turn_id, "req:prompt", PROMPT_DIGEST);
    drop(journal);

    // Exactly 64 characters, so the column CHECK passes; not lowercase hex.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE provider_requests SET payload_digest = ?1 WHERE request_key = 'req:prompt'",
        params![PROMPT_DIGEST.to_uppercase()],
    )
    .expect("smuggle digest");
    drop(raw);

    let mut reopened = ProviderJournal::open(private.path()).expect("reopen");
    let error = reopened.turn_requests(turn_id).expect_err("digest refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("payload_digest"));
    let error = reopened
        .recover_attempt("attempt:a")
        .expect_err("recovery refusal");
    assert_eq!(error.category(), "corrupt");
}

#[test]
fn a_hand_written_over_long_key_surfaces_as_corruption() {
    let (private, mut journal) = journal();
    let (process_id, _session_id, _turn_id) = live_turn(&mut journal);
    drop(journal);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE provider_processes SET attempt_id = ?1 WHERE process_id = ?2",
        params!["a".repeat(4096), process_id],
    )
    .expect("smuggle key");
    drop(raw);

    let reopened = ProviderJournal::open(private.path()).expect("reopen");
    let error = reopened.process(process_id).expect_err("length refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("attempt_id"));
}

#[test]
fn reopen_keeps_wal_foreign_keys_and_durable_rows() {
    let (private, mut journal) = journal();
    let (_process_id, session_id, turn_id) = live_turn(&mut journal);
    record_request(&mut journal, turn_id, "req:prompt", PROMPT_DIGEST);
    drop(journal);

    let raw = Connection::open(private.path()).expect("inspect pragmas");
    let mode: String = raw
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(mode, "wal");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user version");
    assert_eq!(version, PROVIDER_JOURNAL_SCHEMA_VERSION);
    drop(raw);

    let mut reopened = ProviderJournal::open(private.path()).expect("reopen");
    assert_eq!(reopened.turn_requests(turn_id).expect("requests").len(), 1);
    // The API refuses an absent parent before SQLite's foreign key ever
    // matters; the constraint is a backstop for writers that bypass this type.
    let error = reopened
        .open_turn(TurnOpening {
            session_id: session_id + 999,
            ordinal: 1,
            turn_key: "turn:orphan",
            opened_ms: 30,
        })
        .expect_err("orphan turn refusal");
    assert_eq!(error.category(), "not_found");
}

// ---------------------------------------------------------------------------
// CHECK-constraint audit: a NULL must not slip a terminal coupling
//
// SQLite treats a CHECK that evaluates to NULL as *satisfied*, so a coupling
// written over a nullable column as a bare comparison admits the very row it was
// written to refuse. Every terminal coupling in this schema is stated in
// `IS NULL`/`IS NOT NULL` terms rather than in comparisons, so none of them can
// evaluate to NULL at all — and this test is what stops one of them from being
// restated as a comparison later. Each refusal is paired with the legal terminal
// row the coupling must still admit.
// ---------------------------------------------------------------------------

/// Runs one raw statement per case and asserts every one of them is refused.
fn each_refused(raw: &Connection, cases: &[(&str, &str)]) {
    for (what, statement) in cases {
        assert!(
            raw.execute(statement, []).is_err(),
            "the database must refuse {what}"
        );
    }
}

/// Runs one raw statement per case and asserts every one of them is admitted.
fn each_admitted(raw: &Connection, cases: &[(&str, &str)]) {
    for (what, statement) in cases {
        raw.execute(statement, [])
            .unwrap_or_else(|error| panic!("the database must admit {what}: {error}"));
    }
}

#[test]
fn a_null_never_slips_the_terminal_state_couplings() {
    let (private, mut journal) = journal();
    let (process_id, session_id, turn_id) = live_turn(&mut journal);
    assert_eq!((process_id, session_id, turn_id), (1, 1, 1));
    drop(journal);

    let raw = Connection::open(private.path()).expect("raw write");
    each_refused(
        &raw,
        &[
            (
                "a process that exited at no instant",
                "INSERT INTO provider_processes
                     (spawn_key, attempt_id, provider_kind, executable_digest,
                      spawned_ms, revision, state, exited_ms)
                 VALUES ('spawn:audit', 'attempt:audit', 'kind',
                         'abababababababababababababababababababababababababababababababab',
                         0, 1, 'exited', NULL)",
            ),
            (
                "a live process that exited anyway",
                "UPDATE provider_processes SET exited_ms = 5 WHERE process_id = 1",
            ),
            (
                "a session that closed at no instant",
                "INSERT INTO provider_sessions
                     (process_id, provider_session_key, opened_ms, revision,
                      state, closed_ms)
                 VALUES (1, 'session:audit', 0, 1, 'closed', NULL)",
            ),
            (
                "a turn that aborted at no instant",
                "INSERT INTO provider_turns
                     (session_id, ordinal, turn_key, opened_ms, revision,
                      state, closed_ms)
                 VALUES (1, 7, 'turn:audit', 0, 1, 'aborted', NULL)",
            ),
            (
                "an answered request that settled at no instant",
                "INSERT INTO provider_requests
                     (turn_id, request_key, direction, payload_digest, created_ms,
                      revision, outcome, response_digest, failure_reason, settled_ms)
                 VALUES (1, 'req:audit-a', 'to_provider',
                         'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                         0, 1, 'answered',
                         'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef',
                         NULL, NULL)",
            ),
            (
                "an answered request with no answer",
                "INSERT INTO provider_requests
                     (turn_id, request_key, direction, payload_digest, created_ms,
                      revision, outcome, response_digest, failure_reason, settled_ms)
                 VALUES (1, 'req:audit-b', 'to_provider',
                         'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                         0, 1, 'answered', NULL, NULL, 5)",
            ),
            (
                "a failed request with no stated reason",
                "INSERT INTO provider_requests
                     (turn_id, request_key, direction, payload_digest, created_ms,
                      revision, outcome, response_digest, failure_reason, settled_ms)
                 VALUES (1, 'req:audit-c', 'to_provider',
                         'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                         0, 1, 'failed', NULL, NULL, 5)",
            ),
            (
                "a pending request that already settled",
                "INSERT INTO provider_requests
                     (turn_id, request_key, direction, payload_digest, created_ms,
                      revision, outcome, response_digest, failure_reason, settled_ms)
                 VALUES (1, 'req:audit-d', 'to_provider',
                         'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                         0, 1, 'pending', NULL, NULL, 5)",
            ),
        ],
    );

    // Tightness, not mere strictness: every legal terminal shape still lands.
    each_admitted(
        &raw,
        &[
            (
                "a process that exited at an instant",
                "INSERT INTO provider_processes
                     (spawn_key, attempt_id, provider_kind, executable_digest,
                      spawned_ms, revision, state, exited_ms)
                 VALUES ('spawn:audit', 'attempt:audit', 'kind',
                         'abababababababababababababababababababababababababababababababab',
                         0, 1, 'exited', 5)",
            ),
            (
                "a session that closed at an instant",
                "INSERT INTO provider_sessions
                     (process_id, provider_session_key, opened_ms, revision,
                      state, closed_ms)
                 VALUES (1, 'session:audit', 0, 1, 'closed', 5)",
            ),
            (
                "a turn that aborted at an instant",
                "INSERT INTO provider_turns
                     (session_id, ordinal, turn_key, opened_ms, revision,
                      state, closed_ms)
                 VALUES (1, 7, 'turn:audit', 0, 1, 'aborted', 5)",
            ),
            (
                "an answered request carrying its answer and its instant",
                "INSERT INTO provider_requests
                     (turn_id, request_key, direction, payload_digest, created_ms,
                      revision, outcome, response_digest, failure_reason, settled_ms)
                 VALUES (1, 'req:audit-a', 'to_provider',
                         'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                         0, 1, 'answered',
                         'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef',
                         NULL, 5)",
            ),
            (
                "a failed request carrying its reason and its instant",
                "INSERT INTO provider_requests
                     (turn_id, request_key, direction, payload_digest, created_ms,
                      revision, outcome, response_digest, failure_reason, settled_ms)
                 VALUES (1, 'req:audit-c', 'to_provider',
                         'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
                         0, 1, 'failed', NULL, 'provider hung up', 5)",
            ),
        ],
    );
}
