// SPDX-License-Identifier: Elastic-2.0

//! The native Batch control surface, live over the real local socket.
//!
//! Nothing here is a unit test of the batch types — `automonique-protocol` owns
//! those, and `automonique-store` owns the registry's own invariants. What is
//! proved here is the thing neither can prove alone: a membership declared
//! through the socket lands in durable rows, comes back through the same socket
//! in ordinal order, survives the process that declared it, rolls up to a batch
//! state derived from the members beside it, and is refused in the operator's own
//! vocabulary when a report does not follow the lattice or a caller's revision
//! has gone stale.
//!
//! Every request is encoded by the protocol's own encoder and every answer is
//! decoded by its own decoder. A receipt this file assembled, or a page no
//! decoder admitted, would prove nothing.
//!
//! # What this surface still does not do
//!
//! Nothing here submits, schedules or runs anything, and these tests do not
//! pretend otherwise: [`a_registered_batch_causes_no_run_to_exist`] is the
//! assertion that the Runs lane is exactly as empty after a whole batch has been
//! registered and driven to completion as it was before, which is the honest
//! shape of "a batch names submissions, it does not make them".

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use automonique_daemon::{Daemon, DaemonConfig};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::approval_api::{
    ApprovalCursor, ApprovalPageSize, ApprovalRequest, ApprovalResponse, ListApprovals,
};
use automonique_protocol::automation::AutomationActor;
use automonique_protocol::automation_api::{
    AutomationId, AutomationRequest, AutomationResponse, RegisterAutomation,
};
use automonique_protocol::batch_api::{
    AdvanceMember, BatchContinuation, BatchCursor, BatchDetailResult, BatchListPage, BatchPageSize,
    BatchRefusal, BatchRequest, BatchResponse, ListBatches, MAX_BATCH_CONTROL_MEMBERS,
    RegisterBatch,
};
use automonique_protocol::batch_runner::{
    BatchId, BatchLabel, BatchMemberKey, BatchState, ConcurrencyPolicy, MemberProgress,
};
use automonique_protocol::codec::{
    Envelope, FrameDecode, MajorVersion, MessageKind, ProtocolName, RequestId, decode_frame,
    encode_frame,
};
use automonique_protocol::journal::ActionOutcome;
use automonique_protocol::runs_api::{
    ListRuns, PageSize, RunState, RunStateFilter, RunsRequest, RunsResponse,
};
use automonique_protocol::wire::{JsonValue, Message};
use automonique_store::batch_registry::BatchRegistry;

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
/// a malformed registration must receive.
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
        RequestId::new("batch-live-admin").expect("request ID"),
        command,
    )
    .to_message()
    .expect("encode request")
    .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the admin lane answered");
    AdminResponse::from_canonical_bytes(&response).expect("admitted response")
}

/// Ask the Batch lane one question over the same socket the other four use.
///
/// The answer must carry the request's own correlation identifier: an answer to
/// somebody else's question would otherwise pass every content assertion below.
fn batch(config: &DaemonConfig, request: &BatchRequest) -> BatchResponse {
    let payload = request
        .to_message()
        .expect("encode batch request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the batch lane answered");
    let response = BatchResponse::from_canonical_bytes(&response).expect("admitted batch response");
    assert_eq!(
        response.request_id().as_str(),
        request.request_id().as_str(),
        "the answer was not correlated to the question",
    );
    response
}

fn identity(value: &str) -> BatchId {
    BatchId::new(value).expect("batch identity")
}

fn key(value: &str) -> BatchMemberKey {
    BatchMemberKey::new(value).expect("member key")
}

fn request_id(label: &str) -> RequestId {
    RequestId::new(label).expect("request ID")
}

/// Declare one batch and return whatever the daemon answered.
fn present(
    config: &DaemonConfig,
    label: &str,
    batch_id: &str,
    members: &[&str],
    concurrency: ConcurrencyPolicy,
) -> BatchResponse {
    batch(
        config,
        &BatchRequest::RegisterBatch {
            request_id: request_id(label),
            registration: RegisterBatch::new(
                identity(batch_id),
                Some(BatchLabel::new("nightly").expect("label")),
                concurrency,
                members.iter().map(|value| key(value)).collect(),
            )
            .expect("registration"),
        },
    )
}

/// Register one batch and return the row it landed at and the instant it holds.
fn register(
    config: &DaemonConfig,
    label: &str,
    batch_id: &str,
    members: &[&str],
    concurrency: ConcurrencyPolicy,
) -> (u64, i64) {
    let answer = present(config, label, batch_id, members, concurrency);
    // A landed write answers `accepted`, not `completed`: the rows are committed
    // and nothing they record has taken effect, because nothing in this build
    // acts on them.
    assert_eq!(answer.outcome(), ActionOutcome::Accepted);
    let BatchResponse::Registered { receipt, .. } = answer else {
        panic!("expected a registered batch, got the answer above")
    };
    assert_eq!(receipt.batch_id().as_str(), batch_id);
    assert_eq!(receipt.member_count(), members.len());
    assert_eq!(receipt.revision(), 1);
    assert!(receipt.created_at().as_millis() > 0);
    (receipt.entry_id(), receipt.created_at().as_millis())
}

/// Report one member's progress and return whatever the daemon answered.
fn report(
    config: &DaemonConfig,
    label: &str,
    batch_id: &str,
    member_key: &str,
    expected_revision: u64,
    progress: MemberProgress,
    last_sequence: u64,
) -> BatchResponse {
    batch(
        config,
        &BatchRequest::AdvanceMember {
            request_id: request_id(label),
            advance: AdvanceMember::new(
                identity(batch_id),
                key(member_key),
                expected_revision,
                progress,
                last_sequence,
            )
            .expect("advance"),
        },
    )
}

/// Advance one member and return the revision the next advance must expect.
fn advance(
    config: &DaemonConfig,
    label: &str,
    batch_id: &str,
    member_key: &str,
    expected_revision: u64,
    progress: MemberProgress,
    last_sequence: u64,
) -> u64 {
    let answer = report(
        config,
        label,
        batch_id,
        member_key,
        expected_revision,
        progress,
        last_sequence,
    );
    assert_eq!(answer.outcome(), ActionOutcome::Accepted);
    let BatchResponse::MemberAdvanced { receipt, .. } = answer else {
        panic!("expected an advanced member, got the answer above")
    };
    assert_eq!(receipt.member_key().as_str(), member_key);
    assert_eq!(receipt.progress(), progress);
    assert_eq!(receipt.last_sequence(), last_sequence);
    assert_eq!(
        receipt.revision(),
        expected_revision + 1,
        "an accepted advance did not move the revision by exactly one",
    );
    receipt.revision()
}

/// Drive one member from `unsubmitted` all the way to a terminal progress.
///
/// The lattice is walked in full rather than jumped, because the registry
/// refuses the jump — which is the point of the walk.
fn drive(config: &DaemonConfig, label: &str, batch_id: &str, member_key: &str, end: RunState) {
    let revision = advance(
        config,
        &format!("{label}-ready"),
        batch_id,
        member_key,
        1,
        MemberProgress::Run(RunState::Ready),
        0,
    );
    let revision = advance(
        config,
        &format!("{label}-running"),
        batch_id,
        member_key,
        revision,
        MemberProgress::Run(RunState::Running),
        1,
    );
    advance(
        config,
        &format!("{label}-end"),
        batch_id,
        member_key,
        revision,
        MemberProgress::Run(end),
        2,
    );
}

/// One batch in full, or a panic naming what came back instead.
fn detail(config: &DaemonConfig, label: &str, batch_id: &str) -> BatchDetailResult {
    let answer = batch(
        config,
        &BatchRequest::BatchDetail {
            request_id: request_id(label),
            batch_id: identity(batch_id),
        },
    );
    match answer {
        BatchResponse::BatchDetail { detail, .. } => detail,
        other => panic!("expected a detail view, got {other:?}"),
    }
}

/// Every batch the daemon lists, at the largest page.
fn listed(config: &DaemonConfig, label: &str) -> BatchListPage {
    page_of(
        config,
        label,
        ListBatches::new(BatchCursor::START, BatchPageSize::MAX),
    )
}

fn page_of(config: &DaemonConfig, label: &str, query: ListBatches) -> BatchListPage {
    let answer = batch(
        config,
        &BatchRequest::ListBatches {
            request_id: request_id(label),
            query,
        },
    );
    match answer {
        BatchResponse::BatchList { page, .. } => page,
        other => panic!("expected a page, got {other:?}"),
    }
}

/// How many batches the durable file itself holds, read outside the daemon.
fn durable_count(config: &DaemonConfig) -> usize {
    BatchRegistry::open(config.batch_registry_path())
        .expect("open registry")
        .batch_count()
        .expect("count")
}

/// Every run the daemon knows about, over the live Runs lane.
fn runs(config: &DaemonConfig, label: &str) -> usize {
    let request = RunsRequest::ListRuns {
        request_id: request_id(label),
        query: ListRuns::new(RunStateFilter::any(), None, PageSize::MAX),
    };
    let payload = request
        .to_message()
        .expect("encode runs request")
        .to_canonical_bytes();
    let response = exchange(config, &payload).expect("the runs lane answered");
    match RunsResponse::from_canonical_bytes(&response).expect("admitted runs response") {
        RunsResponse::RunList { page, .. } => page.runs().len(),
        other => panic!("expected a run listing, got {other:?}"),
    }
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
fn a_registered_batch_is_listed_and_reads_back_in_ordinal_order_at_unsubmitted() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // Before anything is registered the listing is empty and says so as a
    // complete page rather than as a refusal.
    let empty = listed(&config, "list-empty");
    assert!(empty.entries().is_empty());
    assert_eq!(empty.continuation(), BatchContinuation::Complete);

    let (entry_id, created_at_ms) = register(
        &config,
        "register-1",
        "nightly-eval",
        // Deliberately not in sorted order: the declaration order is what
        // becomes the ordinals, and a registry that sorted would silently
        // re-order the batch.
        &["zulu", "alpha", "mike"],
        ConcurrencyPolicy::bounded_parallel(2).expect("ceiling"),
    );

    let page = listed(&config, "list-one");
    assert_eq!(page.entries().len(), 1);
    assert_eq!(page.continuation(), BatchContinuation::Complete);
    let row = &page.entries()[0];
    assert_eq!(row.batch_id().as_str(), "nightly-eval");
    assert_eq!(row.entry_id(), entry_id);
    assert_eq!(row.label().map(BatchLabel::as_str), Some("nightly"));
    assert_eq!(
        row.concurrency(),
        ConcurrencyPolicy::BoundedParallel { max_in_flight: 2 },
    );
    assert_eq!(row.created_at().as_millis(), created_at_ms);
    assert_eq!(row.revision(), 1);

    // The detail read answers the same batch row, plus the membership.
    let view = detail(&config, "detail-1", "nightly-eval");
    assert_eq!(view.batch(), row);
    assert_eq!(
        view.members()
            .iter()
            .map(|member| (member.key().as_str(), member.ordinal()))
            .collect::<Vec<_>>(),
        vec![("zulu", 0), ("alpha", 1), ("mike", 2)],
        "the membership came back in some order other than the one declared",
    );
    for member in view.members() {
        assert_eq!(member.progress(), MemberProgress::Unsubmitted);
        assert_eq!(member.last_sequence(), 0);
        // Registration is the only writer of `unsubmitted`, and it writes one.
        assert_eq!(member.revision(), 1);
    }
    // Nothing has begun, so the batch is pending. Derived from the members
    // above, never stored.
    assert_eq!(view.rolled_up_state(), BatchState::Pending);

    // A batch nobody registered is refused by name rather than answered with an
    // empty membership — those are different answers.
    assert_eq!(
        batch(
            &config,
            &BatchRequest::BatchDetail {
                request_id: request_id("detail-missing"),
                batch_id: identity("never-declared"),
            },
        ),
        BatchResponse::Refused {
            request_id: request_id("detail-missing"),
            refusal: BatchRefusal::UnknownBatch,
        },
    );
    serving.shutdown(&config);
    assert_eq!(durable_count(&config), 1);
}

#[test]
fn a_member_walks_the_lattice_and_the_detail_reflects_every_step() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(
        &config,
        "register-1",
        "nightly-eval",
        &["record-1", "record-2"],
        ConcurrencyPolicy::Sequential,
    );

    // unsubmitted -> ready. The one edge no event causes, so the sequence stays
    // at zero on both sides.
    let mut revision = advance(
        &config,
        "ready",
        "nightly-eval",
        "record-1",
        1,
        MemberProgress::Run(RunState::Ready),
        0,
    );
    let view = detail(&config, "detail-ready", "nightly-eval");
    assert_eq!(
        view.members()[0].progress(),
        MemberProgress::Run(RunState::Ready)
    );
    assert_eq!(view.members()[0].last_sequence(), 0);
    // The sibling did not move: an advance is member-scoped in both directions.
    assert_eq!(view.members()[1].progress(), MemberProgress::Unsubmitted);
    assert_eq!(view.members()[1].revision(), 1);
    // Neither member has started, so the batch is still pending.
    assert_eq!(view.rolled_up_state(), BatchState::Pending);

    // ready -> running, and then running -> running at a higher sequence, which
    // is a writer observing a run that moved without ending.
    revision = advance(
        &config,
        "running",
        "nightly-eval",
        "record-1",
        revision,
        MemberProgress::Run(RunState::Running),
        4,
    );
    let view = detail(&config, "detail-running", "nightly-eval");
    assert_eq!(view.members()[0].last_sequence(), 4);
    // One member under way and one not: the batch is running.
    assert_eq!(view.rolled_up_state(), BatchState::Running);

    revision = advance(
        &config,
        "still-running",
        "nightly-eval",
        "record-1",
        revision,
        MemberProgress::Run(RunState::Running),
        9,
    );
    assert_eq!(
        detail(&config, "detail-still-running", "nightly-eval").members()[0].last_sequence(),
        9,
    );

    // running -> completed. The single terminal event.
    advance(
        &config,
        "completed",
        "nightly-eval",
        "record-1",
        revision,
        MemberProgress::Run(RunState::Completed),
        10,
    );
    let view = detail(&config, "detail-completed", "nightly-eval");
    assert_eq!(
        view.members()[0].progress(),
        MemberProgress::Run(RunState::Completed)
    );
    // One ended and one never started: still running, because the batch has not
    // finished until every member has.
    assert_eq!(view.rolled_up_state(), BatchState::Running);

    // Drive the second member to the same end and the whole batch completes.
    drive(
        &config,
        "record-2",
        "nightly-eval",
        "record-2",
        RunState::Completed,
    );
    assert_eq!(
        detail(&config, "detail-all-completed", "nightly-eval").rolled_up_state(),
        BatchState::Completed,
    );
    serving.shutdown(&config);
}

#[test]
fn the_batch_state_is_rolled_up_live_from_whatever_the_members_ended_at() {
    let (_root, config) = fixture();
    let serving = serve(&config);

    // Each batch ends at a different mix, and the derived word is a different
    // one. The rollup is exercised over the live socket rather than in memory.
    for (batch_id, ends, expected) in [
        (
            "all-completed",
            vec![RunState::Completed, RunState::Completed],
            BatchState::Completed,
        ),
        (
            "one-failed",
            vec![RunState::Completed, RunState::Failed],
            BatchState::Failed,
        ),
        (
            "one-timed-out",
            vec![RunState::Cancelled, RunState::TimedOut],
            BatchState::Failed,
        ),
        (
            "all-cancelled",
            vec![RunState::Cancelled, RunState::Cancelled],
            BatchState::Cancelled,
        ),
        (
            "mixed",
            vec![RunState::Completed, RunState::Cancelled],
            BatchState::Mixed,
        ),
    ] {
        let members: Vec<String> = (0..ends.len()).map(|index| format!("m{index}")).collect();
        let borrowed: Vec<&str> = members.iter().map(String::as_str).collect();
        register(
            &config,
            &format!("register-{batch_id}"),
            batch_id,
            &borrowed,
            ConcurrencyPolicy::Sequential,
        );
        // Part-way through, with one member terminal and one not, the batch is
        // running whatever the ends will be.
        drive(
            &config,
            &format!("{batch_id}-0"),
            batch_id,
            &members[0],
            ends[0],
        );
        assert_eq!(
            detail(&config, &format!("detail-{batch_id}-part"), batch_id).rolled_up_state(),
            BatchState::Running,
            "{batch_id} was terminal before every member was",
        );
        for (index, end) in ends.iter().enumerate().skip(1) {
            drive(
                &config,
                &format!("{batch_id}-{index}"),
                batch_id,
                &members[index],
                *end,
            );
        }
        let view = detail(&config, &format!("detail-{batch_id}"), batch_id);
        assert_eq!(
            view.rolled_up_state(),
            expected,
            "{batch_id} rolled up to the wrong state",
        );
        assert!(view.rolled_up_state().is_terminal());
        assert_eq!(
            view.members()
                .iter()
                .map(|member| member.progress())
                .collect::<Vec<_>>(),
            ends.iter()
                .map(|end| MemberProgress::Run(*end))
                .collect::<Vec<_>>(),
        );
    }
    serving.shutdown(&config);
}

#[test]
fn an_illegal_transition_and_a_stale_revision_answer_differently_and_write_nothing() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(
        &config,
        "register-1",
        "nightly-eval",
        &["record-1"],
        ConcurrencyPolicy::Sequential,
    );

    // The lattice has no `unsubmitted -> running` edge: a member exists before
    // its submission does, and the jump would claim a submission nobody made.
    for (label, progress, sequence) in [
        ("jump-running", MemberProgress::Run(RunState::Running), 1),
        (
            "jump-completed",
            MemberProgress::Run(RunState::Completed),
            1,
        ),
        ("stay-put", MemberProgress::Unsubmitted, 0),
    ] {
        assert_eq!(
            report(
                &config,
                label,
                "nightly-eval",
                "record-1",
                1,
                progress,
                sequence,
            ),
            BatchResponse::Refused {
                request_id: request_id(label),
                refusal: BatchRefusal::IllegalTransition,
            },
            "{label} was accepted",
        );
    }

    // The legal edge is accepted, so the refusals above are the lattice and not
    // a handler that refuses everything.
    let revision = advance(
        &config,
        "ready",
        "nightly-eval",
        "record-1",
        1,
        MemberProgress::Run(RunState::Ready),
        0,
    );
    assert_eq!(revision, 2);

    // A stale revision is a conflict rather than a rejection: the request was
    // well-formed and the row simply moved. The durable revision travels with
    // the answer so a retry needs no second read.
    let answer = report(
        &config,
        "stale",
        "nightly-eval",
        "record-1",
        1,
        MemberProgress::Run(RunState::Running),
        1,
    );
    assert_eq!(answer.outcome(), ActionOutcome::Conflict);
    assert_eq!(
        answer,
        BatchResponse::Conflict {
            request_id: request_id("stale"),
            expected_revision: 1,
            durable_revision: 2,
        },
    );

    // A sequence that does not advance past the durable one is its own refusal,
    // and is not the same answer as a conflict.
    let revision = advance(
        &config,
        "running",
        "nightly-eval",
        "record-1",
        revision,
        MemberProgress::Run(RunState::Running),
        5,
    );
    assert_eq!(
        report(
            &config,
            "rewind",
            "nightly-eval",
            "record-1",
            revision,
            MemberProgress::Run(RunState::Completed),
            5,
        ),
        BatchResponse::Refused {
            request_id: request_id("rewind"),
            refusal: BatchRefusal::SequenceRegression,
        },
    );

    // A member the batch never named, and a batch nobody registered, are
    // different refusals — one is a typo in the key, the other in the identity.
    assert_eq!(
        report(
            &config,
            "unknown-member",
            "nightly-eval",
            "record-9",
            1,
            MemberProgress::Run(RunState::Ready),
            0,
        ),
        BatchResponse::Refused {
            request_id: request_id("unknown-member"),
            refusal: BatchRefusal::UnknownMember,
        },
    );
    assert_eq!(
        report(
            &config,
            "unknown-batch",
            "weekly-eval",
            "record-1",
            1,
            MemberProgress::Run(RunState::Ready),
            0,
        ),
        BatchResponse::Refused {
            request_id: request_id("unknown-batch"),
            refusal: BatchRefusal::UnknownBatch,
        },
    );

    // Nothing above moved the row: it is still where the last accepted advance
    // left it.
    let view = detail(&config, "detail-after-refusals", "nightly-eval");
    assert_eq!(
        view.members()[0].progress(),
        MemberProgress::Run(RunState::Running)
    );
    assert_eq!(view.members()[0].last_sequence(), 5);
    assert_eq!(view.members()[0].revision(), revision);
    serving.shutdown(&config);
}

#[test]
fn a_second_registration_of_one_identity_is_refused_and_resets_nothing() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let (entry_id, _) = register(
        &config,
        "register-1",
        "nightly-eval",
        &["record-1", "record-2"],
        ConcurrencyPolicy::Sequential,
    );
    drive(
        &config,
        "record-1",
        "nightly-eval",
        "record-1",
        RunState::Completed,
    );

    // A second registration of the same identity is refused — even naming the
    // same members, and even naming different ones. Accepting it would reset the
    // progress the advance above recorded, which is the one thing the registry
    // exists to prevent.
    for (label, members) in [
        ("duplicate-same", vec!["record-1", "record-2"]),
        ("duplicate-different", vec!["record-3"]),
    ] {
        assert_eq!(
            present(
                &config,
                label,
                "nightly-eval",
                &members,
                ConcurrencyPolicy::Sequential,
            ),
            BatchResponse::Refused {
                request_id: request_id(label),
                refusal: BatchRefusal::AlreadyRegistered,
            },
            "{label} was accepted",
        );
    }

    // The batch is exactly as it was: one row, the original membership, and the
    // progress the advance left.
    assert_eq!(listed(&config, "list-after-duplicates").entries().len(), 1);
    let view = detail(&config, "detail-after-duplicates", "nightly-eval");
    assert_eq!(view.batch().entry_id(), entry_id);
    assert_eq!(view.members().len(), 2);
    assert_eq!(
        view.members()[0].progress(),
        MemberProgress::Run(RunState::Completed)
    );
    assert_eq!(view.rolled_up_state(), BatchState::Running);
    serving.shutdown(&config);
    assert_eq!(durable_count(&config), 1);
}

/// A registration the protocol will not decode never reaches the daemon.
///
/// The socket closes without an answer and no durable state is touched. That
/// silence is the assertion: an *answered* empty batch would mean the bounded
/// membership rules had been dropped from the decoder and were being decided
/// somewhere further in.
#[test]
fn a_membership_the_protocol_refuses_never_reaches_the_daemon() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(
        &config,
        "register-1",
        "nightly-eval",
        &["record-1"],
        ConcurrencyPolicy::Sequential,
    );

    let over_ceiling: Vec<String> = (0..=MAX_BATCH_CONTROL_MEMBERS)
        .map(|index| format!("\"record-{index}\""))
        .collect();
    for (label, members, concurrency) in [
        (
            "an empty membership",
            "[]".to_owned(),
            r#"{"kind":"sequential","max_in_flight":null}"#,
        ),
        (
            "a repeated member key",
            r#"["record-1","record-1"]"#.to_owned(),
            r#"{"kind":"sequential","max_in_flight":null}"#,
        ),
        (
            "a membership above this lane's ceiling",
            format!("[{}]", over_ceiling.join(",")),
            r#"{"kind":"sequential","max_in_flight":null}"#,
        ),
        (
            "a ceiling that admits nothing",
            r#"["record-9"]"#.to_owned(),
            r#"{"kind":"bounded_parallel","max_in_flight":0}"#,
        ),
        (
            "a ceiling no batch could reach",
            r#"["record-9"]"#.to_owned(),
            r#"{"kind":"bounded_parallel","max_in_flight":257}"#,
        ),
        (
            "a sequential policy carrying a ceiling",
            r#"["record-9"]"#.to_owned(),
            r#"{"kind":"sequential","max_in_flight":2}"#,
        ),
        (
            "a concurrency kind this build does not define",
            r#"["record-9"]"#.to_owned(),
            r#"{"kind":"unbounded","max_in_flight":null}"#,
        ),
    ] {
        let payload = format!(
            r#"{{"body":{{"batch_id":"weekly-eval","concurrency":{concurrency},"label":null,"members":{members}}},"kind":"register_batch","protocol":"automonique.batch.control","request_id":"hand-rolled","version":1}}"#
        );
        assert!(
            exchange(&config, payload.as_bytes()).is_none(),
            "{label} was answered instead of refused before the daemon",
        );
    }

    // An advance whose sequence contradicts its progress is refused the same
    // way, before any durable row is read.
    for (label, progress, sequence) in [
        ("a ready member at a non-zero sequence", "ready", 7),
        ("a running member at sequence zero", "running", 0),
        ("a progress word this build does not define", "finished", 1),
    ] {
        let payload = format!(
            r#"{{"body":{{"batch_id":"nightly-eval","expected_revision":1,"last_sequence":{sequence},"member_key":"record-1","state":"{progress}"}},"kind":"advance_member","protocol":"automonique.batch.control","request_id":"hand-rolled","version":1}}"#
        );
        assert!(
            exchange(&config, payload.as_bytes()).is_none(),
            "{label} was answered instead of refused before the daemon",
        );
    }

    // Nothing was written, so the refusals above cost no durable state.
    assert_eq!(listed(&config, "list-untouched").entries().len(), 1);
    assert_eq!(
        detail(&config, "detail-untouched", "nightly-eval").members()[0].progress(),
        MemberProgress::Unsubmitted,
    );
    serving.shutdown(&config);
    assert_eq!(durable_count(&config), 1);
}

#[test]
fn a_listing_pages_over_the_durable_registry_and_refuses_a_cursor_it_never_wrote() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let mut entries = Vec::new();
    for index in 0..5 {
        let batch_id = format!("batch-{index}");
        let (entry_id, _) = register(
            &config,
            &format!("register-{index}"),
            &batch_id,
            &["record-1"],
            ConcurrencyPolicy::Sequential,
        );
        entries.push((batch_id, entry_id));
    }

    // Two pages of two and a final page of one, walked by the cursor the daemon
    // itself reported. Nothing is re-served and nothing is skipped.
    let mut cursor = BatchCursor::START;
    let mut seen = Vec::new();
    loop {
        let page = page_of(
            &config,
            &format!("page-{}", cursor.position()),
            ListBatches::new(cursor, BatchPageSize::new(2).expect("page size")),
        );
        assert!(page.entries().len() <= 2);
        for row in page.entries() {
            seen.push((row.batch_id().as_str().to_owned(), row.entry_id()));
        }
        match page.continuation() {
            BatchContinuation::More(next) => cursor = next,
            BatchContinuation::Complete => break,
        }
    }
    assert_eq!(seen, entries, "the walk did not visit every batch once");

    // A cursor above everything recorded is a refusal by name rather than an
    // empty page: "your cursor is gone" and "there is nothing to show" are
    // different answers, and this registry never loses a row.
    let highest = entries.last().expect("a batch").1;
    for (label, position) in [("above-highest", highest + 1), ("far-above", u64::MAX >> 1)] {
        assert_eq!(
            batch(
                &config,
                &BatchRequest::ListBatches {
                    request_id: request_id(label),
                    query: ListBatches::new(BatchCursor::new(position), BatchPageSize::MAX,),
                },
            ),
            BatchResponse::Refused {
                request_id: request_id(label),
                refusal: BatchRefusal::CursorOutOfRange,
            },
            "{label}",
        );
    }

    // The highest recorded cursor itself is legal and answers an empty complete
    // page, so the refusal above is a bound rather than an off-by-one.
    let page = page_of(
        &config,
        "at-highest",
        ListBatches::new(BatchCursor::new(highest), BatchPageSize::MAX),
    );
    assert!(page.entries().is_empty());
    assert_eq!(page.continuation(), BatchContinuation::Complete);
    serving.shutdown(&config);
}

#[test]
fn an_empty_registry_refuses_a_cursor_it_never_wrote() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    // Position zero is where a listing begins and is always legal.
    assert!(listed(&config, "list-empty").entries().is_empty());
    // Anything above it names a row nothing ever wrote.
    assert_eq!(
        batch(
            &config,
            &BatchRequest::ListBatches {
                request_id: request_id("empty-cursor"),
                query: ListBatches::new(BatchCursor::new(1), BatchPageSize::MAX),
            },
        ),
        BatchResponse::Refused {
            request_id: request_id("empty-cursor"),
            refusal: BatchRefusal::CursorOutOfRange,
        },
    );
    serving.shutdown(&config);
}

#[test]
fn registered_batches_and_member_progress_survive_the_process_that_recorded_them() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    let (first_entry, first_instant) = register(
        &config,
        "register-1",
        "nightly-eval",
        &["record-1", "record-2"],
        ConcurrencyPolicy::bounded_parallel(2).expect("ceiling"),
    );
    register(
        &config,
        "register-2",
        "weekly-eval",
        &["record-3"],
        ConcurrencyPolicy::Sequential,
    );
    drive(
        &config,
        "record-1",
        "nightly-eval",
        "record-1",
        RunState::Failed,
    );
    let mid_revision = advance(
        &config,
        "record-2-ready",
        "nightly-eval",
        "record-2",
        1,
        MemberProgress::Run(RunState::Ready),
        0,
    );
    serving.shutdown(&config);

    // A new generation opens the same registry file and answers from it. Nothing
    // was rebuilt in memory: the process that took these declarations is gone.
    let serving = serve(&config);
    let page = listed(&config, "list-after-restart");
    assert_eq!(page.entries().len(), 2);
    assert_eq!(page.entries()[0].batch_id().as_str(), "nightly-eval");
    assert_eq!(page.entries()[0].entry_id(), first_entry);
    assert_eq!(page.entries()[0].created_at().as_millis(), first_instant);
    assert_eq!(
        page.entries()[0].concurrency(),
        ConcurrencyPolicy::BoundedParallel { max_in_flight: 2 },
    );
    assert_eq!(page.entries()[1].batch_id().as_str(), "weekly-eval");
    assert_eq!(
        page.entries()[1].concurrency(),
        ConcurrencyPolicy::Sequential
    );

    let view = detail(&config, "detail-after-restart", "nightly-eval");
    assert_eq!(
        view.members()[0].progress(),
        MemberProgress::Run(RunState::Failed)
    );
    assert_eq!(view.members()[0].last_sequence(), 2);
    assert_eq!(
        view.members()[1].progress(),
        MemberProgress::Run(RunState::Ready)
    );
    assert_eq!(view.members()[1].revision(), mid_revision);
    assert_eq!(view.rolled_up_state(), BatchState::Running);

    // A duplicate registration across the restart is still a duplicate: the
    // identity is durable, so the exclusion it buys survives the process too.
    assert_eq!(
        present(
            &config,
            "duplicate-after-restart",
            "nightly-eval",
            &["record-1", "record-2"],
            ConcurrencyPolicy::Sequential,
        ),
        BatchResponse::Refused {
            request_id: request_id("duplicate-after-restart"),
            refusal: BatchRefusal::AlreadyRegistered,
        },
    );

    // And the fencing revision survives too: the advance the old process left
    // behind is the one the new process expects next.
    let revision = advance(
        &config,
        "record-2-running-after-restart",
        "nightly-eval",
        "record-2",
        mid_revision,
        MemberProgress::Run(RunState::Running),
        1,
    );
    advance(
        &config,
        "record-2-cancelled",
        "nightly-eval",
        "record-2",
        revision,
        MemberProgress::Run(RunState::Cancelled),
        2,
    );
    // One failed and one cancelled, all terminal: a lost member outranks a
    // cancelled one, so the batch failed.
    assert_eq!(
        detail(&config, "detail-terminal", "nightly-eval").rolled_up_state(),
        BatchState::Failed,
    );
    serving.shutdown(&config);

    // And the durable file itself holds both batches, so the page above is not a
    // listing that merely happened to remember.
    assert_eq!(durable_count(&config), 2);
    let registry = BatchRegistry::open(config.batch_registry_path()).expect("open registry");
    let stored = registry
        .batch("nightly-eval")
        .expect("read")
        .expect("nightly-eval is registered");
    assert_eq!(
        stored.members[0].progress,
        automonique_store::batch_registry::MemberProgress::Run(
            automonique_store::run_index::RunSpoolState::Failed
        ),
        "the refused registrations overwrote a durable member",
    );
    assert_eq!(stored.batch.created_at_ms, first_instant);
    assert_eq!(stored.batch.revision, 1);
}

#[test]
fn one_socket_places_each_frame_by_the_protocol_it_declares() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    register(
        &config,
        "register-1",
        "nightly-eval",
        &["record-1"],
        ConcurrencyPolicy::Sequential,
    );

    // A frame naming a protocol this socket does not serve is placed by nobody.
    // It earns no answer at all — not an admin refusal, which would mean the
    // admin lane had read a body it does not own.
    let stranger = Message::new(
        Envelope::new(
            ProtocolName::new("automonique.stranger").expect("protocol name"),
            MajorVersion::new(1).expect("version"),
            RequestId::new("stranger-1").expect("request ID"),
            MessageKind::new("list_batches").expect("kind"),
        ),
        JsonValue::Object(Vec::new()),
    )
    .to_canonical_bytes();
    assert!(
        exchange(&config, &stranger).is_none(),
        "an unplaceable frame was answered",
    );

    // The hyphenated spelling of this lane's own name is not a protocol name the
    // envelope can carry, so a client that guessed it is placed by nobody either.
    let hyphenated = br#"{"body":{"page_size":32,"since":0},"kind":"list_batches","protocol":"automonique.batch-control","request_id":"r","version":1}"#;
    assert!(
        exchange(&config, hyphenated).is_none(),
        "a hyphenated protocol name was answered",
    );

    // A batch kind spelled inside one of the other four envelopes is refused by
    // the lane that owns that envelope's kind set. The five lanes do not fall
    // through to one another.
    for protocol in [
        "automonique.admin",
        "automonique.runs",
        "automonique.automation",
        "automonique.approval",
    ] {
        let misplaced = Message::new(
            Envelope::new(
                ProtocolName::new(protocol).expect("protocol name"),
                MajorVersion::new(1).expect("version"),
                RequestId::new("misplaced-1").expect("request ID"),
                MessageKind::new("register_batch").expect("kind"),
            ),
            JsonValue::Object(Vec::new()),
        )
        .to_canonical_bytes();
        assert!(
            exchange(&config, &misplaced).is_none(),
            "a {protocol} frame naming a batch kind was answered",
        );
    }

    // All five lanes still work, interleaved, on the same live daemon.
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    assert_eq!(runs(&config, "runs-mixed"), 0);
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
    let approval = ApprovalRequest::ListApprovals {
        request_id: RequestId::new("approval-mixed").expect("request ID"),
        query: ListApprovals::new(ApprovalCursor::START, ApprovalPageSize::MAX),
    };
    let payload = approval
        .to_message()
        .expect("encode approval request")
        .to_canonical_bytes();
    let response = exchange(&config, &payload).expect("the approval lane answered");
    assert!(matches!(
        ApprovalResponse::from_canonical_bytes(&response).expect("admitted approval response"),
        ApprovalResponse::ApprovalList { .. }
    ));
    assert_eq!(listed(&config, "list-mixed").entries().len(), 1);
    assert!(matches!(
        call(&config, AdminCommand::Status),
        AdminResponse::Status { .. }
    ));
    serving.shutdown(&config);
}

/// A batch names submissions; it does not make them.
///
/// Nothing in this build submits, schedules or runs anything on a batch's
/// behalf, and this is the honest shape of that claim: the Runs lane is exactly
/// as empty after a whole batch has been registered and driven to `completed` as
/// it was before it existed. A member's `completed` is a caller's claim about a
/// run the run index has never heard of.
#[test]
fn a_registered_batch_causes_no_run_to_exist() {
    let (_root, config) = fixture();
    let serving = serve(&config);
    assert_eq!(runs(&config, "runs-before"), 0);

    register(
        &config,
        "register-1",
        "nightly-eval",
        &["record-1", "record-2"],
        ConcurrencyPolicy::bounded_parallel(2).expect("ceiling"),
    );
    assert_eq!(
        runs(&config, "runs-after-register"),
        0,
        "registering a batch created a run",
    );

    for member in ["record-1", "record-2"] {
        drive(&config, member, "nightly-eval", member, RunState::Completed);
    }
    // Every member claims it completed, and the batch rolls up to `completed`.
    assert_eq!(
        detail(&config, "detail-completed", "nightly-eval").rolled_up_state(),
        BatchState::Completed,
    );
    // The run index disagrees, and it is the one that would know: no run was
    // ever submitted, so there is nothing for a member's claim to be about.
    assert_eq!(
        runs(&config, "runs-after-completion"),
        0,
        "advancing a batch's members to completed created a run",
    );

    // The daemon's own counters are unmoved for the same reason.
    let AdminResponse::Status { status, .. } = call(&config, AdminCommand::Status) else {
        panic!("status response")
    };
    assert_eq!(status.running(), 0);
    assert_eq!(status.inbox_pending(), 0);
    assert_eq!(status.outbox_pending(), 0);
    assert!(status.accepting_intake());
    serving.shutdown(&config);
}
