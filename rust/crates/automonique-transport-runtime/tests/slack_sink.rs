// SPDX-License-Identifier: Elastic-2.0

//! Durable Slack sink invariants, exercised against a real temporary log.
//!
//! Every frame here is produced by `parse_slack_envelope` rather than
//! hand-assembled, because `SlackEnvelope` has no public constructor and the
//! sink's whole job is to bind what the parser produced. Durable state is read
//! back through the sink after the fact, so a receipt that looks right while
//! nothing was written fails these tests.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use automonique_store::slack_ingress::{
    MAX_DISPOSITION_PAGE, SlackDispositionKind, SlackIngressLog, SlackRecordOutcome,
};
use automonique_transport_runtime::{
    Clock, ClockFailure, SlackSinkFailure, StoreSlackDurableSink, slack_content_digest,
};
use automonique_transports::{
    SlackAccessPolicy, SlackAppId, SlackEnvelope, SlackPrincipal, parse_slack_envelope,
};
use tempfile::TempDir;

const APP: &str = "A0FIRST";
const TEXT: &str = "deploy the thing";

struct PrivateLog {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateLog {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("slack-ingress.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone)]
struct TestClock {
    now_ms: Arc<AtomicI64>,
    unavailable: Arc<AtomicBool>,
}

impl TestClock {
    fn new(now_ms: i64) -> Self {
        Self {
            now_ms: Arc::new(AtomicI64::new(now_ms)),
            unavailable: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set(&self, now_ms: i64) {
        self.now_ms.store(now_ms, Ordering::Release);
    }

    fn break_clock(&self) {
        self.unavailable.store(true, Ordering::Release);
    }

    fn repair(&self) {
        self.unavailable.store(false, Ordering::Release);
    }
}

impl Clock for TestClock {
    fn now_ms(&mut self) -> Result<i64, ClockFailure> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(ClockFailure::Unavailable);
        }
        Ok(self.now_ms.load(Ordering::Acquire))
    }
}

fn policy(app: &str, allowed_user: &str) -> SlackAccessPolicy {
    SlackAccessPolicy::new(
        SlackAppId::new(app).expect("app id"),
        [SlackPrincipal::new("T01", "C01", allowed_user).expect("principal")],
    )
    .expect("policy")
}

fn message_frame(envelope_id: &str, ts: &str, user: &str, text: &str, retry: u32) -> Vec<u8> {
    format!(
        r#"{{"envelope_id":"{envelope_id}","type":"events_api","retry_attempt":{retry},
            "payload":{{"type":"event_callback","team_id":"T01",
            "event":{{"type":"message","channel":"C01","user":"{user}",
            "ts":"{ts}","text":"{text}"}}}}}}"#
    )
    .into_bytes()
}

fn parse(frame: &[u8], policy: &SlackAccessPolicy) -> SlackEnvelope {
    parse_slack_envelope(frame, policy).expect("frame parses")
}

fn admitted_envelope(envelope_id: &str, ts: &str, text: &str, retry: u32) -> SlackEnvelope {
    parse(
        &message_frame(envelope_id, ts, "U01", text, retry),
        &policy(APP, "U01"),
    )
}

fn open_sink(private: &PrivateLog, clock: TestClock) -> StoreSlackDurableSink<TestClock> {
    let log = SlackIngressLog::open(private.path()).expect("open log");
    StoreSlackDurableSink::new(log, clock, SlackAppId::new(APP).expect("app id"))
}

fn source_key(ts: &str) -> String {
    format!("slack:{APP}:T01:C01:{ts}")
}

#[test]
fn an_admitted_frame_is_recorded_with_the_exact_content_digest() {
    let private = PrivateLog::new();
    let clock = TestClock::new(4_000);
    let mut sink = open_sink(&private, clock);
    assert_eq!(sink.app_id().as_str(), APP);

    let envelope = admitted_envelope("Ev001", "1700000000.000100", TEXT, 0);
    let receipt = sink.record_disposition(&envelope).expect("record");
    assert_eq!(receipt.outcome, SlackRecordOutcome::Recorded);
    assert_eq!(receipt.disposition, SlackDispositionKind::Admitted);
    assert!(!receipt.is_replay());
    assert!(receipt.entry_id > 0);

    let entry = sink
        .recorded(&source_key("1700000000.000100"))
        .expect("read")
        .expect("row exists");
    assert_eq!(entry.entry_id, receipt.entry_id);
    assert_eq!(entry.source_key, source_key("1700000000.000100"));
    assert_eq!(entry.app_id, APP);
    assert_eq!(entry.disposition, SlackDispositionKind::Admitted);
    assert_eq!(entry.content_digest, Some(slack_content_digest(TEXT)));
    assert_eq!(entry.envelope_id, "Ev001");
    assert_eq!(entry.retry_attempt, 0);
    assert_eq!(entry.recorded_at_ms, 4_000);

    // The digest is a binding, not the text: a different message cannot land on
    // the same name.
    assert_ne!(
        entry.content_digest,
        Some(slack_content_digest("deploy the other thing"))
    );
}

#[test]
fn a_redelivery_replays_the_first_recording_and_rewrites_nothing() {
    let private = PrivateLog::new();
    let clock = TestClock::new(4_000);
    let mut sink = open_sink(&private, clock.clone());
    let first = sink
        .record_disposition(&admitted_envelope("Ev001", "1700000000.000100", TEXT, 0))
        .expect("first delivery");

    // Slack redelivers the same event under a fresh ack key, a raised retry
    // counter and a later clock.
    clock.set(70_000);
    let replay = sink
        .record_disposition(&admitted_envelope("Ev002", "1700000000.000100", TEXT, 2))
        .expect("redelivery is recorded history, not a refusal");
    assert_eq!(replay.outcome, SlackRecordOutcome::AlreadyRecorded);
    assert!(replay.is_replay());
    assert_eq!(replay.entry_id, first.entry_id);
    assert_eq!(replay.disposition, SlackDispositionKind::Admitted);

    let page = sink
        .recorded_since(0, MAX_DISPOSITION_PAGE)
        .expect("recovery page");
    assert_eq!(page.len(), 1, "a replay must not insert a second row");
    assert_eq!(page[0].envelope_id, "Ev001");
    assert_eq!(page[0].retry_attempt, 0);
    assert_eq!(page[0].recorded_at_ms, 4_000);
}

#[test]
fn a_redelivery_that_changes_the_text_conflicts_and_records_nothing() {
    let private = PrivateLog::new();
    let clock = TestClock::new(4_000);
    let mut sink = open_sink(&private, clock);
    sink.record_disposition(&admitted_envelope("Ev001", "1700000000.000100", TEXT, 0))
        .expect("first delivery");

    let failure = sink
        .record_disposition(&admitted_envelope(
            "Ev002",
            "1700000000.000100",
            "something else entirely",
            1,
        ))
        .expect_err("a redelivery may not rewrite what was decided");
    assert_eq!(failure, SlackSinkFailure::Conflict);

    let page = sink
        .recorded_since(0, MAX_DISPOSITION_PAGE)
        .expect("recovery page");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].content_digest, Some(slack_content_digest(TEXT)));
    assert_eq!(page[0].envelope_id, "Ev001");
}

#[test]
fn a_denied_frame_records_a_content_free_row() {
    let private = PrivateLog::new();
    let clock = TestClock::new(4_000);
    let mut sink = open_sink(&private, clock);

    // Same workspace and channel, a user the policy never named.
    let envelope = parse(
        &message_frame("Ev010", "1700000000.000900", "U99", TEXT, 0),
        &policy(APP, "U01"),
    );
    let receipt = sink.record_disposition(&envelope).expect("record");
    assert_eq!(receipt.outcome, SlackRecordOutcome::Recorded);
    assert_eq!(receipt.disposition, SlackDispositionKind::Denied);

    let entry = sink
        .recorded(&source_key("1700000000.000900"))
        .expect("read")
        .expect("row exists");
    assert_eq!(entry.disposition, SlackDispositionKind::Denied);
    assert_eq!(
        entry.content_digest, None,
        "a denied frame retains no content and therefore no digest"
    );
}

#[test]
fn frames_without_a_deduplication_identity_are_not_recordable() {
    let private = PrivateLog::new();
    let clock = TestClock::new(4_000);
    let mut sink = open_sink(&private, clock);
    let policy = policy(APP, "U01");

    let unrecordable: Vec<Vec<u8>> = vec![
        br#"{"type":"hello","num_connections":1}"#.to_vec(),
        br#"{"envelope_id":"Ev020","type":"slash_commands","payload":{"command":"/run"}}"#.to_vec(),
        br#"{"envelope_id":"Ev021","type":"not_a_slack_type"}"#.to_vec(),
        br#"{"envelope_id":"Ev022","type":"events_api","payload":{"type":"event_callback",
             "team_id":"T01","event":{"type":"reaction_added","channel":"C01","user":"U01"}}}"#
            .to_vec(),
        br#"{"envelope_id":"Ev023","type":"events_api","payload":{"type":"event_callback",
             "team_id":"T01","event":{"type":"message","subtype":"channel_join",
             "channel":"C01","user":"U01","ts":"1700000000.001000","text":"joined"}}}"#
            .to_vec(),
    ];
    for frame in unrecordable {
        let envelope = parse(&frame, &policy);
        assert_eq!(
            sink.record_disposition(&envelope)
                .expect_err("no dedup identity, no row"),
            SlackSinkFailure::NotRecordable
        );
    }

    let page = sink
        .recorded_since(0, MAX_DISPOSITION_PAGE)
        .expect("recovery page");
    assert!(page.is_empty(), "nothing unrecordable may reach the log");
}

#[test]
fn an_envelope_parsed_under_another_apps_policy_is_refused() {
    let private = PrivateLog::new();
    let clock = TestClock::new(4_000);
    let mut sink = open_sink(&private, clock);

    let foreign = parse(
        &message_frame("Ev030", "1700000000.000100", "U01", TEXT, 0),
        &policy("A0SECOND", "U01"),
    );
    assert_eq!(
        sink.record_disposition(&foreign)
            .expect_err("a frame from another app cannot be filed under this one"),
        SlackSinkFailure::Inconsistent
    );
    assert!(
        sink.recorded_since(0, MAX_DISPOSITION_PAGE)
            .expect("recovery page")
            .is_empty()
    );

    // The same event under this sink's own app records normally, so the refusal
    // above is about the app binding and nothing else.
    sink.record_disposition(&admitted_envelope("Ev030", "1700000000.000100", TEXT, 0))
        .expect("own app records");
    assert_eq!(
        sink.recorded_since(0, MAX_DISPOSITION_PAGE)
            .expect("recovery page")
            .len(),
        1
    );
}

#[test]
fn a_clock_failure_records_nothing_and_recovers() {
    let private = PrivateLog::new();
    let clock = TestClock::new(4_000);
    let mut sink = open_sink(&private, clock.clone());

    clock.break_clock();
    let envelope = admitted_envelope("Ev040", "1700000000.000100", TEXT, 0);
    assert_eq!(
        sink.record_disposition(&envelope)
            .expect_err("an unobservable instant is not a recording"),
        SlackSinkFailure::Unavailable
    );
    assert!(
        sink.recorded(&source_key("1700000000.000100"))
            .expect("read")
            .is_none(),
        "a failed clock must leave the log untouched"
    );

    clock.repair();
    clock.set(9_000);
    let receipt = sink.record_disposition(&envelope).expect("record");
    assert_eq!(receipt.outcome, SlackRecordOutcome::Recorded);
    assert_eq!(
        sink.recorded(&source_key("1700000000.000100"))
            .expect("read")
            .expect("row")
            .recorded_at_ms,
        9_000
    );
}

#[test]
fn a_full_log_refuses_a_new_frame_but_still_answers_a_replay() {
    let private = PrivateLog::new();
    let log = SlackIngressLog::open_with_capacity(private.path(), 1).expect("open at capacity");
    let mut sink = StoreSlackDurableSink::new(
        log,
        TestClock::new(4_000),
        SlackAppId::new(APP).expect("app"),
    );

    sink.record_disposition(&admitted_envelope("Ev050", "1700000000.000100", TEXT, 0))
        .expect("first delivery");
    assert_eq!(
        sink.record_disposition(&admitted_envelope("Ev051", "1700000000.000200", TEXT, 0))
            .expect_err("a frame that cannot be recorded must not look acked"),
        SlackSinkFailure::LogFull
    );
    let replay = sink
        .record_disposition(&admitted_envelope("Ev052", "1700000000.000100", TEXT, 1))
        .expect("a replay writes nothing and must survive a full log");
    assert_eq!(replay.outcome, SlackRecordOutcome::AlreadyRecorded);

    let page = sink
        .recorded_since(0, MAX_DISPOSITION_PAGE)
        .expect("recovery page");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].source_key, source_key("1700000000.000100"));
}

#[test]
fn recovery_pages_are_bounded_and_survive_a_reopen() {
    let private = PrivateLog::new();
    let clock = TestClock::new(1_000);
    let mut sink = open_sink(&private, clock.clone());
    for (index, ts) in [
        "1700000000.000100",
        "1700000000.000200",
        "1700000000.000300",
    ]
    .iter()
    .enumerate()
    {
        clock.set(1_000 + i64::try_from(index).expect("small index") * 10);
        sink.record_disposition(&admitted_envelope("Ev060", ts, TEXT, 0))
            .expect("record");
    }

    assert_eq!(
        sink.recorded_since(0, 0)
            .expect_err("an unbounded page has no spelling"),
        SlackSinkFailure::Inconsistent
    );
    assert_eq!(
        sink.recorded_since(0, MAX_DISPOSITION_PAGE + 1)
            .expect_err("the page bound is exact"),
        SlackSinkFailure::Inconsistent
    );
    assert_eq!(sink.recorded_since(0, 2).expect("bounded page").len(), 2);
    assert_eq!(sink.recorded_since(1_020, 8).expect("since page").len(), 1);

    let (log, _) = sink.into_parts();
    drop(log);

    let reopened = open_sink(&private, TestClock::new(2_000));
    let page = reopened
        .recorded_since(0, MAX_DISPOSITION_PAGE)
        .expect("recovery page after reopen");
    assert_eq!(page.len(), 3);
    assert_eq!(page[0].source_key, source_key("1700000000.000100"));
    assert_eq!(page[2].source_key, source_key("1700000000.000300"));
    assert_eq!(page[2].recorded_at_ms, 1_020);
}
