// SPDX-License-Identifier: Elastic-2.0

//! The native Approval decision surface, live over the real local socket.
//!
//! Nothing here is a unit test of the decision types — `automonique-protocol`
//! owns those, and `automonique-store` owns the ledger's own invariants. What is
//! proved here is the thing neither can prove alone: a decision entered through
//! the socket lands in a durable write-once row, comes back through the same
//! socket unchanged, survives the process that recorded it, replays without
//! writing a second row, and is refused in the operator's own vocabulary when
//! the key is already spoken for.
//!
//! Every request is encoded by the protocol's own encoder and every answer is
//! decoded by its own decoder. A receipt this file assembled, or a page no
//! decoder admitted, would prove nothing.
//!
//! # What this surface still does not do
//!
//! Nothing here gates anything, and these tests do not pretend otherwise:
//! [`a_recorded_decision_allows_nothing_because_nothing_consults_it`] is the
//! assertion that the daemon behaves identically on both sides of a recorded
//! `granted` and a recorded `denied`, which is the honest shape of "a recorded
//! approval allows no action today".

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse, DaemonState};
use automonique_protocol::approval_api::{
    ApprovalContinuation, ApprovalCursor, ApprovalDecision, ApprovalDisposition, ApprovalKey,
    ApprovalListPage, ApprovalPageSize, ApprovalRecordView, ApprovalRefusal, ApprovalRequest,
    ApprovalResponse, ApprovalSubject, ApprovalsBySubject, ConflictField, Decider, ListApprovals,
    RecordApproval,
};
use automonique_protocol::automation::AutomationActor;
use automonique_protocol::automation_api::{
    AutomationId, AutomationRequest, AutomationResponse, RegisterAutomation,
};
use automonique_protocol::codec::{
    Envelope, FrameDecode, MajorVersion, MessageKind, ProtocolName, RequestId, decode_frame,
    encode_frame,
};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::runs_api::{
    ListRuns, PageSize, RunStateFilter, RunsRequest, RunsResponse,
};
use automonique_protocol::wire::{JsonValue, Message};
use automonique_store::approval_ledger::ApprovalLedger;

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    std::fs::create_dir(&runtime).expect("runtime root");
    std::fs::create_dir(&state).expect("state root");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    (
        root,
        DaemonConfig {
            runtime_root: runtime,
            state_root: state,
        },
    )
}

/// Send one canonical payload and read one back, or report that the daemon
/// closed the connection without answering.
///
/// Both outcomes are legitimate and they are different: a placed frame earns a
/// typed answer, and a frame no lane will place earns silence. Collapsing them
/// into a panic would make the second untestable, and the second is exactly what
/// a malformed decision request must receive.
fn exchange(config: &DaemonConfig, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read deadline");
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("frame request");
    stream.write_all(&frame).expect("write request");
    let mut prefix = [0_u8; 4];
    if stream.read_exact(&mut prefix).is_err() {
        return None;
    }
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut response[4..])
        .expect("response body");
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).expect("response frame")
    else {
        panic!("complete response was incomplete")
    };
    Some(payload.to_vec())
}

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    let payload = AdminRequest::new(
        RequestId::new("approval-live-admin").expect("request ID"),
        command,
    )
    .to_message()
    .expect("encode request")
    .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the admin lane answered");
    AdminResponse::from_canonical_bytes(&response).expect("admitted response")
}

/// Ask the Approval lane one question over the same socket the other three use.
///
/// The answer must carry the request's own correlation identifier: an answer to
/// somebody else's question would otherwise pass every content assertion below.
fn approval(config: &DaemonConfig, request: &ApprovalRequest) -> ApprovalResponse {
    let payload = request
        .to_message()
        .expect("encode approval request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the approval lane answered");
    let response =
        ApprovalResponse::from_canonical_bytes(&response).expect("admitted approval response");
    assert_eq!(
        response.request_id().as_str(),
        request.request_id().as_str(),
        "the answer was not correlated to the question",
    );
    response
}

fn key(value: &str) -> ApprovalKey {
    ApprovalKey::new(value).expect("approval key")
}

fn subject(value: &str) -> ApprovalSubject {
    ApprovalSubject::new(value).expect("subject")
}

fn decider(value: &str) -> Decider {
    Decider::new(value).expect("decider")
}

fn request_id(label: &str) -> RequestId {
    RequestId::new(label).expect("request ID")
}

/// Present one decision and return whatever the daemon answered.
fn present(
    config: &DaemonConfig,
    label: &str,
    approval_key: &str,
    what: &str,
    decision: ApprovalDecision,
    who: &str,
) -> ApprovalResponse {
    approval(
        config,
        &ApprovalRequest::RecordApproval {
            request_id: request_id(label),
            decision: RecordApproval::new(key(approval_key), subject(what), decision, decider(who)),
        },
    )
}

/// Record one decision and return the row it landed at and the instant it holds.
fn record(
    config: &DaemonConfig,
    label: &str,
    approval_key: &str,
    what: &str,
    decision: ApprovalDecision,
    who: &str,
) -> (u64, i64) {
    let answer = present(config, label, approval_key, what, decision, who);
    // A landed write answers `accepted`, not `completed`: the row is committed
    // and the decision it records has nowhere to take effect, because nothing in
    // this build consults it.
    assert_eq!(answer.outcome(), ActionOutcome::Accepted);
    let ApprovalResponse::Recorded { receipt, .. } = answer else {
        panic!("expected a recorded decision, got the answer above")
    };
    assert_eq!(receipt.approval_key().as_str(), approval_key);
    assert_eq!(receipt.decision(), decision);
    assert_eq!(
        receipt.disposition(),
        ApprovalDisposition::Recorded,
        "a first recording reported itself as a replay",
    );
    assert!(receipt.decided_at().as_millis() > 0);
    (receipt.entry_id(), receipt.decided_at().as_millis())
}

/// One decision in full, or a panic naming what came back instead.
fn detail(config: &DaemonConfig, label: &str, approval_key: &str) -> ApprovalRecordView {
    let answer = approval(
        config,
        &ApprovalRequest::ApprovalDetail {
            request_id: request_id(label),
            approval_key: key(approval_key),
        },
    );
    match answer {
        ApprovalResponse::ApprovalDetail { record, .. } => record,
        other => panic!("expected a record, got {other:?}"),
    }
}

/// Every decision the daemon lists, at the largest page.
fn listed(config: &DaemonConfig, label: &str) -> ApprovalListPage {
    page_of(
        config,
        label,
        ListApprovals::new(ApprovalCursor::START, ApprovalPageSize::MAX),
    )
}

fn page_of(config: &DaemonConfig, label: &str, query: ListApprovals) -> ApprovalListPage {
    let answer = approval(
        config,
        &ApprovalRequest::ListApprovals {
            request_id: request_id(label),
            query,
        },
    );
    match answer {
        ApprovalResponse::ApprovalList { page, .. } => page,
        other => panic!("expected a page, got {other:?}"),
    }
}

fn by_subject(
    config: &DaemonConfig,
    label: &str,
    what: &str,
    since: ApprovalCursor,
    page_size: ApprovalPageSize,
) -> ApprovalListPage {
    let answer = approval(
        config,
        &ApprovalRequest::ApprovalsBySubject {
            request_id: request_id(label),
            query: ApprovalsBySubject::new(subject(what), since, page_size),
        },
    );
    match answer {
        ApprovalResponse::ApprovalList { page, .. } => page,
        other => panic!("expected a page, got {other:?}"),
    }
}

/// How many rows the durable file itself holds, read outside the daemon.
fn durable_count(config: &DaemonConfig) -> usize {
    ApprovalLedger::open(config.approval_ledger_path())
        .expect("open ledger")
        .decision_count()
        .expect("count")
}

fn wait_for_socket(config: &DaemonConfig) {
    // Generous on purpose. Everything before the bind is disk-bound — several
    // SQLite databases opened `synchronous = FULL`, each fsyncing its own WAL —
    // so a short deadline here measures the test host under concurrent load
    // rather than the daemon.
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), automonique_daemon::DaemonError>>>,
}

fn serve(config: &DaemonConfig) -> Serving {
    let daemon = Daemon::open(config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&thread_stop));
    wait_for_socket(config);
    Serving {
        stop,
        thread: Some(thread),
    }
}

impl Serving {
    fn shutdown(mut self, config: &DaemonConfig) {
        assert!(matches!(
            call(config, AdminCommand::Shutdown),
            AdminResponse::ShutdownAccepted { .. }
        ));
        self.thread
            .take()
            .expect("running")
            .join()
            .expect("daemon thread")
            .expect("clean stop");
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            let _ = thread.join();
        }
    }
}

#[test]
fn a_recorded_decision_is_listed_readable_in_full_and_found_by_its_subject() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // Before anything is recorded the listing is empty and says so as a complete
    // page rather than as a refusal.
    let empty = listed(&config, "list-empty");
    assert!(empty.entries().is_empty());
    assert_eq!(empty.continuation(), ApprovalContinuation::Complete);

    let (entry_id, decided_at_ms) = record(
        &config,
        "record-1",
        "deploy-2026-08-13",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );

    let page = listed(&config, "list-one");
    assert_eq!(page.entries().len(), 1);
    assert_eq!(page.continuation(), ApprovalContinuation::Complete);
    let row = &page.entries()[0];
    assert_eq!(row.approval_key().as_str(), "deploy-2026-08-13");
    assert_eq!(row.entry_id(), entry_id);
    assert_eq!(row.subject().as_str(), "command:shutdown");
    assert_eq!(row.decision(), ApprovalDecision::Granted);
    assert_eq!(row.decider().as_str(), "ben");
    assert_eq!(row.decided_at().as_millis(), decided_at_ms);
    // Write-once: the durable column is pinned to one, and the protocol's own
    // decoder refuses anything else, so a rendered one is evidence rather than a
    // constant this test typed out.
    assert_eq!(row.revision(), 1);
    assert!(row.grants());

    // The detail read answers the same row.
    assert_eq!(&detail(&config, "detail-1", "deploy-2026-08-13"), row);

    // And so does the subject listing.
    let by = by_subject(
        &config,
        "by-subject-1",
        "command:shutdown",
        ApprovalCursor::START,
        ApprovalPageSize::MAX,
    );
    assert_eq!(by.entries(), page.entries());

    // A subject nobody decided about is an empty page, not a refusal: the
    // question "what was decided about this" has a true empty answer.
    let none = by_subject(
        &config,
        "by-subject-absent",
        "command:pause-intake",
        ApprovalCursor::START,
        ApprovalPageSize::MAX,
    );
    assert!(none.entries().is_empty());
    assert_eq!(none.continuation(), ApprovalContinuation::Complete);

    // A key nobody recorded is refused by name rather than answered with an
    // empty record — and never as a denial, which is a different answer.
    assert_eq!(
        approval(
            &config,
            &ApprovalRequest::ApprovalDetail {
                request_id: request_id("detail-missing"),
                approval_key: key("never-decided"),
            },
        ),
        ApprovalResponse::Refused {
            request_id: request_id("detail-missing"),
            refusal: ApprovalRefusal::UnknownApproval,
        },
    );
    serving.shutdown(&config);
}

#[test]
fn an_exact_replay_is_idempotent_and_writes_no_second_row() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let (entry_id, decided_at_ms) = record(
        &config,
        "record-1",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );

    // The same decision presented twice more. Each answers the *first*
    // recording's row and instant, and neither writes anything.
    for label in ["replay-1", "replay-2"] {
        let answer = present(
            &config,
            label,
            "deploy-1",
            "command:shutdown",
            ApprovalDecision::Granted,
            "ben",
        );
        assert_eq!(answer.outcome(), ActionOutcome::Accepted);
        let ApprovalResponse::Recorded { receipt, .. } = answer else {
            panic!("a replay was not answered as a recording")
        };
        assert_eq!(
            receipt.disposition(),
            ApprovalDisposition::AlreadyRecorded,
            "a replay claimed to have written a row",
        );
        assert_eq!(receipt.entry_id(), entry_id);
        assert_eq!(
            receipt.decided_at().as_millis(),
            decided_at_ms,
            "a replay rewrote the recorded instant",
        );
    }

    // One row on the wire, and one row in the file. The second is what makes
    // the first mean something: a listing that deduplicated would look the same.
    assert_eq!(listed(&config, "list-after-replays").entries().len(), 1);
    serving.shutdown(&config);
    assert_eq!(durable_count(&config), 1);
}

#[test]
fn a_key_presented_with_a_different_decision_is_a_conflict_and_writes_nothing() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let (entry_id, decided_at_ms) = record(
        &config,
        "record-1",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );

    // Each of the three identity fields, changed one at a time, and the field
    // the answer names is the first that differs in the ledger's own comparison
    // order rather than the one this test changed.
    for (label, what, decision, who, expected) in [
        (
            "conflict-subject",
            "command:pause-intake",
            ApprovalDecision::Granted,
            "ben",
            ConflictField::Subject,
        ),
        (
            "conflict-decision",
            "command:shutdown",
            ApprovalDecision::Denied,
            "ben",
            ConflictField::Decision,
        ),
        (
            "conflict-decider",
            "command:shutdown",
            ApprovalDecision::Granted,
            "dana",
            ConflictField::Decider,
        ),
    ] {
        let answer = present(&config, label, "deploy-1", what, decision, who);
        // A conflict is its own outcome. Reporting it as a rejection would tell
        // a client the request was malformed, and it was not.
        assert_eq!(answer.outcome(), ActionOutcome::Conflict);
        let ApprovalResponse::Conflict {
            field, recorded, ..
        } = answer
        else {
            panic!("{label} was not answered with a conflict")
        };
        assert_eq!(field, expected, "{label} named the wrong field");
        // The conflict carries what the durable row holds, so a caller learns
        // what it collided with without a second read.
        assert_eq!(recorded.entry_id, entry_id);
        assert_eq!(recorded.subject.as_str(), "command:shutdown");
        assert_eq!(recorded.decision, ApprovalDecision::Granted);
        assert_eq!(recorded.decider.as_str(), "ben");
    }

    // Nothing moved: one row, still the original, still at its original instant.
    let page = listed(&config, "list-after-conflicts");
    assert_eq!(page.entries().len(), 1);
    let row = &page.entries()[0];
    assert_eq!(row.entry_id(), entry_id);
    assert_eq!(row.decision(), ApprovalDecision::Granted);
    assert_eq!(row.decider().as_str(), "ben");
    assert_eq!(row.decided_at().as_millis(), decided_at_ms);
    assert_eq!(row.revision(), 1, "a refused write amended a row");

    // Reversing the decision is a new key, and both rows survive. The ledger
    // does not say which one governs, and neither does this lane.
    record(
        &config,
        "record-2",
        "deploy-1-reversed",
        "command:shutdown",
        ApprovalDecision::Denied,
        "dana",
    );
    let history = by_subject(
        &config,
        "by-subject-history",
        "command:shutdown",
        ApprovalCursor::START,
        ApprovalPageSize::MAX,
    );
    assert_eq!(
        history
            .entries()
            .iter()
            .map(|record| (record.approval_key().as_str(), record.decision()))
            .collect::<Vec<_>>(),
        vec![
            ("deploy-1", ApprovalDecision::Granted),
            ("deploy-1-reversed", ApprovalDecision::Denied),
        ],
        "the subject history is not the order the decisions were made in",
    );
    serving.shutdown(&config);
    assert_eq!(durable_count(&config), 2);
}

#[test]
fn a_listing_pages_over_the_durable_ledger_and_a_subject_selects_within_it() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    for (label, approval_key, what, decision) in [
        (
            "record-1",
            "alpha",
            "command:shutdown",
            ApprovalDecision::Granted,
        ),
        (
            "record-2",
            "beta",
            "command:pause-intake",
            ApprovalDecision::Denied,
        ),
        (
            "record-3",
            "gamma",
            "command:shutdown",
            ApprovalDecision::Denied,
        ),
    ] {
        record(&config, label, approval_key, what, decision, "ben");
    }

    // Two at a time, over three rows.
    let two = ApprovalPageSize::new(2).expect("page size");
    let head = page_of(
        &config,
        "page-head",
        ListApprovals::new(ApprovalCursor::START, two),
    );
    assert_eq!(head.entries().len(), 2);
    assert_eq!(head.entries()[0].approval_key().as_str(), "alpha");
    assert_eq!(head.entries()[1].approval_key().as_str(), "beta");
    let ApprovalContinuation::More(cursor) = head.continuation() else {
        panic!("a page that left a row behind reported itself complete")
    };
    assert_eq!(
        cursor.position(),
        head.entries()[1].entry_id(),
        "the cursor is the last entry served, resumed after",
    );

    let tail = page_of(&config, "page-tail", ListApprovals::new(cursor, two));
    assert_eq!(
        tail.entries().len(),
        1,
        "the tail repeated or dropped a row"
    );
    assert_eq!(tail.entries()[0].approval_key().as_str(), "gamma");
    assert_eq!(tail.continuation(), ApprovalContinuation::Complete);

    // A cursor at the last recorded entry is caught up: a complete empty page.
    let caught_up = page_of(
        &config,
        "page-caught-up",
        ListApprovals::new(ApprovalCursor::new(tail.entries()[0].entry_id()), two),
    );
    assert!(caught_up.entries().is_empty());
    assert_eq!(caught_up.continuation(), ApprovalContinuation::Complete);

    // The subject selects rather than truncates: two rows for one subject, one
    // for the other, and the two sets are disjoint and complete.
    let shutdown = by_subject(
        &config,
        "by-subject-shutdown",
        "command:shutdown",
        ApprovalCursor::START,
        ApprovalPageSize::MAX,
    );
    assert_eq!(
        shutdown
            .entries()
            .iter()
            .map(|record| record.approval_key().as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "gamma"],
    );
    let pause = by_subject(
        &config,
        "by-subject-pause",
        "command:pause-intake",
        ApprovalCursor::START,
        ApprovalPageSize::MAX,
    );
    assert_eq!(
        pause
            .entries()
            .iter()
            .map(|record| record.approval_key().as_str())
            .collect::<Vec<_>>(),
        vec!["beta"],
    );

    // The subject listing pages too, and its cursor is a position in the whole
    // ledger rather than in the matching subset: resuming after `alpha`'s entry
    // — which is *not* the row a `command:pause-intake` filter would have
    // selected — still finds `gamma`.
    let one = ApprovalPageSize::new(1).expect("page size");
    let first = by_subject(
        &config,
        "by-subject-page-1",
        "command:shutdown",
        ApprovalCursor::START,
        one,
    );
    assert_eq!(first.entries().len(), 1);
    assert_eq!(first.entries()[0].approval_key().as_str(), "alpha");
    let ApprovalContinuation::More(cursor) = first.continuation() else {
        panic!("a subject page that left a row behind reported itself complete")
    };
    let second = by_subject(
        &config,
        "by-subject-page-2",
        "command:shutdown",
        cursor,
        one,
    );
    assert_eq!(
        second
            .entries()
            .iter()
            .map(|record| record.approval_key().as_str())
            .collect::<Vec<_>>(),
        vec!["gamma"],
    );
    assert_eq!(second.continuation(), ApprovalContinuation::Complete);

    // A cursor above everything recorded is a refusal rather than an empty page,
    // exactly as the ledger decides it: "your cursor names a row that was never
    // written" and "there is nothing to show" are different answers.
    for (label, request) in [
        (
            "page-out-of-range",
            ApprovalRequest::ListApprovals {
                request_id: request_id("page-out-of-range"),
                query: ListApprovals::new(ApprovalCursor::new(4_096), two),
            },
        ),
        (
            "by-subject-out-of-range",
            ApprovalRequest::ApprovalsBySubject {
                request_id: request_id("by-subject-out-of-range"),
                query: ApprovalsBySubject::new(
                    subject("command:shutdown"),
                    ApprovalCursor::new(4_096),
                    two,
                ),
            },
        ),
    ] {
        assert_eq!(
            approval(&config, &request),
            ApprovalResponse::Refused {
                request_id: request_id(label),
                refusal: ApprovalRefusal::CursorOutOfRange,
            },
            "{label}",
        );
    }
    serving.shutdown(&config);
}

#[test]
fn an_empty_ledger_refuses_a_cursor_it_never_wrote() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    // Position zero is where a listing begins and is always legal.
    assert!(listed(&config, "list-empty").entries().is_empty());
    // Anything above it names a row nothing ever wrote.
    assert_eq!(
        approval(
            &config,
            &ApprovalRequest::ListApprovals {
                request_id: request_id("empty-cursor"),
                query: ListApprovals::new(ApprovalCursor::new(1), ApprovalPageSize::MAX),
            },
        ),
        ApprovalResponse::Refused {
            request_id: request_id("empty-cursor"),
            refusal: ApprovalRefusal::CursorOutOfRange,
        },
    );
    serving.shutdown(&config);
}

/// A decision request the protocol will not decode never reaches the daemon.
///
/// The socket closes without an answer and no durable state is touched. That
/// silence is the assertion: an *answered* `maybe` would mean the closed
/// two-word vocabulary had been dropped from the decoder and was being decided
/// somewhere further in.
#[test]
fn an_undefined_decision_word_is_refused_before_the_daemon() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    record(
        &config,
        "record-1",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );

    for (label, body) in [
        (
            "a third decision word",
            br#"{"approval_key":"deploy-2","decider":"ben","decision":"maybe","subject":"command:shutdown"}"#.as_slice(),
        ),
        (
            "a case variant of a defined word",
            br#"{"approval_key":"deploy-2","decider":"ben","decision":"GRANTED","subject":"command:shutdown"}"#.as_slice(),
        ),
        (
            "an empty decider",
            br#"{"approval_key":"deploy-2","decider":"","decision":"granted","subject":"command:shutdown"}"#.as_slice(),
        ),
    ] {
        let payload = [
            br#"{"body":"#.as_slice(),
            body,
            br#","kind":"record_approval","protocol":"automonique.approval","request_id":"hand-rolled","version":1}"#.as_slice(),
        ]
        .concat();
        assert!(
            exchange(&config, &payload).is_none(),
            "{label} was answered instead of refused before the daemon",
        );
    }

    // Nothing was written, so the refusals above cost no durable state.
    assert_eq!(listed(&config, "list-untouched").entries().len(), 1);
    serving.shutdown(&config);
    assert_eq!(durable_count(&config), 1);
}

#[test]
fn recorded_decisions_survive_the_process_that_recorded_them() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let (first_entry, first_instant) = record(
        &config,
        "record-1",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );
    record(
        &config,
        "record-2",
        "deploy-2",
        "command:pause-intake",
        ApprovalDecision::Denied,
        "dana",
    );
    serving.shutdown(&config);

    // A new generation opens the same ledger file and answers from it. Nothing
    // was rebuilt in memory: the process that took these decisions is gone.
    let serving = serve(&config);
    let page = listed(&config, "list-after-restart");
    assert_eq!(page.entries().len(), 2);
    assert_eq!(page.entries()[0].approval_key().as_str(), "deploy-1");
    assert_eq!(page.entries()[0].entry_id(), first_entry);
    assert_eq!(page.entries()[0].decided_at().as_millis(), first_instant);
    let second = &page.entries()[1];
    assert_eq!(second.approval_key().as_str(), "deploy-2");
    assert_eq!(second.subject().as_str(), "command:pause-intake");
    assert_eq!(second.decision(), ApprovalDecision::Denied);
    assert_eq!(second.decider().as_str(), "dana");
    assert!(!second.grants());

    // A replay across the restart is still a replay: the key is durable, so the
    // idempotency it buys survives the process too.
    let answer = present(
        &config,
        "replay-after-restart",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );
    let ApprovalResponse::Recorded { receipt, .. } = answer else {
        panic!("a replay after restart was not answered as a recording")
    };
    assert_eq!(receipt.disposition(), ApprovalDisposition::AlreadyRecorded);
    assert_eq!(receipt.entry_id(), first_entry);
    assert_eq!(receipt.decided_at().as_millis(), first_instant);

    // So is a conflict.
    let answer = present(
        &config,
        "conflict-after-restart",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Denied,
        "ben",
    );
    assert!(matches!(answer, ApprovalResponse::Conflict { .. }));

    // A third decision recorded after the restart continues the same order, so
    // the ledger resumed rather than restarted.
    record(
        &config,
        "record-3",
        "deploy-3",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );
    let page = listed(&config, "list-after-third");
    assert_eq!(page.entries().len(), 3);
    assert_eq!(page.entries()[2].approval_key().as_str(), "deploy-3");
    assert!(page.entries()[0].entry_id() < page.entries()[2].entry_id());
    serving.shutdown(&config);

    // And the durable file itself holds three rows, so the page above is not a
    // listing that merely happened to deduplicate.
    assert_eq!(durable_count(&config), 3);
    let ledger = ApprovalLedger::open(config.approval_ledger_path()).expect("open ledger");
    let stored = ledger
        .entry("deploy-1")
        .expect("read")
        .expect("deploy-1 is recorded");
    assert_eq!(
        stored.decision,
        automonique_store::approval_ledger::ApprovalDecision::Granted,
        "the conflicting presentation overwrote the durable decision",
    );
    assert_eq!(stored.decided_at_ms, first_instant);
    assert_eq!(stored.revision, 1);
}

#[test]
fn one_socket_places_each_frame_by_the_protocol_it_declares() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    record(
        &config,
        "record-1",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );

    // A frame naming a protocol this socket does not serve is placed by nobody.
    // It earns no answer at all — not an admin refusal, which would mean the
    // admin lane had read a body it does not own.
    let stranger = Message::new(
        Envelope::new(
            ProtocolName::new("automonique.stranger").expect("protocol name"),
            MajorVersion::new(1).expect("version"),
            RequestId::new("stranger-1").expect("request ID"),
            MessageKind::new("list_approvals").expect("kind"),
        ),
        JsonValue::Object(Vec::new()),
    )
    .to_canonical_bytes();
    assert!(
        exchange(&config, &stranger).is_none(),
        "an unplaceable frame was answered",
    );

    // An approval kind spelled inside one of the other three envelopes is
    // refused by the lane that owns that envelope's kind set. The four lanes do
    // not fall through to one another.
    for protocol in [
        "automonique.admin",
        "automonique.runs",
        "automonique.automation",
    ] {
        let misplaced = Message::new(
            Envelope::new(
                ProtocolName::new(protocol).expect("protocol name"),
                MajorVersion::new(1).expect("version"),
                RequestId::new("misplaced-1").expect("request ID"),
                MessageKind::new("record_approval").expect("kind"),
            ),
            JsonValue::Object(Vec::new()),
        )
        .to_canonical_bytes();
        assert!(
            exchange(&config, &misplaced).is_none(),
            "a {protocol} frame naming an approval kind was answered",
        );
    }

    // All four lanes still work, interleaved, on the same live daemon.
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    let runs = RunsRequest::ListRuns {
        request_id: RequestId::new("runs-mixed").expect("request ID"),
        query: ListRuns::new(RunStateFilter::any(), None, PageSize::MAX),
    };
    let payload = runs
        .to_message()
        .expect("encode runs request")
        .to_canonical_bytes();
    let response = exchange(&config, &payload).expect("the runs lane answered");
    assert!(matches!(
        RunsResponse::from_canonical_bytes(&response).expect("admitted runs response"),
        RunsResponse::RunList { .. }
    ));
    let automation = AutomationRequest::RegisterAutomation {
        request_id: RequestId::new("automation-mixed").expect("request ID"),
        registration: RegisterAutomation::new(
            AutomationId::new("nightly-report").expect("automation identity"),
            AutomationActor::new("ben").expect("actor"),
        ),
    };
    let payload = automation
        .to_message()
        .expect("encode automation request")
        .to_canonical_bytes();
    let response = exchange(&config, &payload).expect("the automation lane answered");
    assert!(matches!(
        AutomationResponse::from_canonical_bytes(&response).expect("admitted automation response"),
        AutomationResponse::Accepted { .. }
    ));
    assert_eq!(listed(&config, "list-mixed").entries().len(), 1);
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    serving.shutdown(&config);
}

/// A recorded decision is evidence and not a gate.
///
/// Nothing in this build consults the ledger before acting, and this is the
/// honest shape of that claim: the daemon's own counters and its intake switch
/// are exactly as they were, on both sides of a recorded `granted` *and* a
/// recorded `denied`. A `denied` decision about the shutdown command does not
/// close intake, and a `granted` one does not open anything.
#[test]
fn a_recorded_decision_allows_nothing_because_nothing_consults_it() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let AdminResponse::Status { status: before, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };

    record(
        &config,
        "record-granted",
        "deploy-1",
        "command:shutdown",
        ApprovalDecision::Granted,
        "ben",
    );
    record(
        &config,
        "record-denied",
        "deploy-2",
        "command:pause-intake",
        ApprovalDecision::Denied,
        "dana",
    );

    let AdminResponse::Status { status: after, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(after.state(), DaemonState::Ready);
    assert_eq!(after.state(), before.state());
    assert_eq!(after.running(), 0);
    assert_eq!(after.running(), before.running());
    assert_eq!(after.inbox_pending(), before.inbox_pending());
    assert_eq!(after.outbox_pending(), before.outbox_pending());
    // Most pointedly: a decision recorded *about* an admin command changes
    // nothing about that command. Intake is still open, because these are
    // different switches and this one does not pretend to be the other.
    assert!(after.accepting_intake());
    assert_eq!(after.accepting_intake(), before.accepting_intake());
    assert!(!after.intake_paused());

    // The commands the decisions were about still behave exactly as they did:
    // recording an approval for `shutdown` did not shut anything down, and the
    // daemon is still serving.
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    serving.shutdown(&config);
}
