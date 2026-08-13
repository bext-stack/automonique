// SPDX-License-Identifier: Elastic-2.0

//! Durable approval decision ledger invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the ledger and reopen
//! the file: an in-memory ledger cannot pass them, which is the whole reason
//! this module exists.
//!
//! Write-once is asserted from both sides everywhere it matters: the answer the
//! call returns *and* the durable row and row count afterwards. An
//! implementation that answered `AlreadyRecorded` while inserting a second row,
//! or that answered `Conflict` after overwriting the decision, would satisfy
//! only the first half.
//!
//! The hand-written-row tests write rows this API would have refused, using
//! `PRAGMA ignore_check_constraints` where the column CHECK would otherwise stop
//! them. That is the point: a CHECK protects the database from a second writer,
//! and the read path must protect *callers* from a row that got in anyway.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::approval_ledger::{
    APPROVAL_LEDGER_SCHEMA_VERSION, ApprovalDecision, ApprovalDecisionRecord, ApprovalDisposition,
    ApprovalEntry, ApprovalLedger, MAX_APPROVAL_DECISIONS, MAX_APPROVAL_PAGE, MAX_IDENTIFIER_BYTES,
    RetainedApprovalRange,
};
use automonique_store::provider_journal::ApprovalDecision as JournalDecision;
use rusqlite::{Connection, params};
use tempfile::TempDir;

struct PrivateLedger {
    _directory: TempDir,
    path: PathBuf,
}

impl PrivateLedger {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let path = directory.path().join("approvals.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn ledger() -> (PrivateLedger, ApprovalLedger) {
    let private = PrivateLedger::new();
    let opened = ApprovalLedger::open(private.path()).expect("open ledger");
    (private, opened)
}

fn decided<'a>(
    approval_key: &'a str,
    subject: &'a str,
    decision: ApprovalDecision,
    decider: &'a str,
) -> ApprovalDecisionRecord<'a> {
    ApprovalDecisionRecord {
        approval_key,
        subject,
        decision,
        decider,
        decided_at_ms: 1_000,
    }
}

/// The canonical grant used wherever the fields themselves are not the subject
/// of the test.
fn grant(approval_key: &str) -> ApprovalDecisionRecord<'_> {
    decided(
        approval_key,
        "cmd:automonique.admin.shutdown",
        ApprovalDecision::Granted,
        "ops:ada",
    )
}

fn keys(entries: &[ApprovalEntry]) -> Vec<&str> {
    entries
        .iter()
        .map(|entry| entry.approval_key.as_str())
        .collect()
}

/// The whole durable row, as a comparable tuple, for "nothing was written"
/// assertions.
fn snapshot(ledger: &ApprovalLedger, approval_key: &str) -> (String, String, String, i64, u64) {
    let entry = ledger
        .entry(approval_key)
        .expect("read entry")
        .expect("entry present");
    (
        entry.subject,
        entry.decision.as_str().to_owned(),
        entry.decider,
        entry.decided_at_ms,
        entry.revision,
    )
}

// ---------------------------------------------------------------------------
// Storage discipline
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_ledger_stamps_its_schema_version() {
    let (private, ledger) = ledger();
    assert_eq!(ledger.path(), private.path());
    assert_eq!(ledger.capacity(), MAX_APPROVAL_DECISIONS);
    assert_eq!(ledger.decision_count().expect("count"), 0);
    assert_eq!(ledger.retained_range().expect("range"), None);
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, APPROVAL_LEDGER_SCHEMA_VERSION);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, ledger) = ledger();
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = ApprovalLedger::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
    assert!(error.to_string().contains("9999"));
}

#[test]
fn a_populated_database_without_our_schema_is_refused() {
    let private = PrivateLedger::new();
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(private.path())
        .expect("private file");

    let raw = Connection::open(private.path()).expect("raw create");
    raw.execute_batch("CREATE TABLE foreign_rows (id INTEGER PRIMARY KEY) STRICT;")
        .expect("foreign table");
    drop(raw);

    // An unstamped database that already holds objects is somebody else's; the
    // ledger refuses it rather than creating its table alongside them.
    let error = ApprovalLedger::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_ledger_file_is_refused() {
    let (private, ledger) = ledger();
    drop(ledger);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = ApprovalLedger::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_group_readable_directory_is_refused() {
    let private = PrivateLedger::new();
    let parent = private.path().parent().expect("parent directory");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750)).expect("loosen directory mode");

    let error = ApprovalLedger::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_capacity_outside_its_bounds_is_refused() {
    let private = PrivateLedger::new();
    for capacity in [0, MAX_APPROVAL_DECISIONS + 1] {
        let error = ApprovalLedger::open_with_capacity(private.path(), capacity)
            .expect_err("capacity refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("capacity"));
    }
}

// ---------------------------------------------------------------------------
// Recording, and write-once
// ---------------------------------------------------------------------------

#[test]
fn a_recorded_decision_reads_back_whole() {
    let (_private, mut ledger) = ledger();
    let receipt = ledger
        .record(decided(
            "apv:1",
            "cmd:automonique.admin.shutdown",
            ApprovalDecision::Granted,
            "ops:ada",
        ))
        .expect("record");
    assert_eq!(receipt.disposition, ApprovalDisposition::Recorded);
    assert_eq!(receipt.decided_at_ms, 1_000);

    let entry = ledger
        .entry("apv:1")
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.entry_id, receipt.entry_id);
    assert_eq!(entry.approval_key, "apv:1");
    assert_eq!(entry.subject, "cmd:automonique.admin.shutdown");
    assert_eq!(entry.decision, ApprovalDecision::Granted);
    assert_eq!(entry.decider, "ops:ada");
    assert_eq!(entry.decided_at_ms, 1_000);
    // Write-once rows have exactly one revision.
    assert_eq!(entry.revision, 1);
    assert!(entry.grants());

    assert_eq!(ledger.decision_count().expect("count"), 1);
}

#[test]
fn a_denial_reads_back_as_a_denial() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(decided(
            "apv:no",
            "effect:deploy:production",
            ApprovalDecision::Denied,
            "ops:ada",
        ))
        .expect("record");

    let entry = ledger
        .entry("apv:no")
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.decision, ApprovalDecision::Denied);
    assert!(!entry.grants());
}

#[test]
fn an_unrecorded_key_is_absent_rather_than_denied() {
    let (_private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");

    // An unrecorded decision and a recorded refusal are different answers.
    assert_eq!(ledger.entry("apv:missing").expect("read entry"), None);
}

#[test]
fn an_exact_replay_answers_already_recorded_and_writes_no_second_row() {
    let (_private, mut ledger) = ledger();
    let first = ledger.record(grant("apv:1")).expect("first recording");
    assert_eq!(first.disposition, ApprovalDisposition::Recorded);

    let replay = ledger.record(grant("apv:1")).expect("replay");
    assert_eq!(replay.disposition, ApprovalDisposition::AlreadyRecorded);
    assert_eq!(replay.entry_id, first.entry_id);

    // The second half: a replay that inserted a second row would still have
    // answered AlreadyRecorded above.
    assert_eq!(ledger.decision_count().expect("count"), 1);
    let page = ledger.page(0, 10).expect("page");
    assert_eq!(keys(&page.entries), vec!["apv:1"]);
}

#[test]
fn an_exact_replay_after_close_and_reopen_is_already_recorded() {
    let private = PrivateLedger::new();
    let first = {
        let mut ledger = ApprovalLedger::open(private.path()).expect("open ledger");
        ledger.record(grant("apv:1")).expect("first recording")
    };
    assert_eq!(first.disposition, ApprovalDisposition::Recorded);

    // The whole point of the module: the answer survives the process that gave
    // it. An in-memory ledger records a second, contradictory decision here.
    let mut reopened = ApprovalLedger::open(private.path()).expect("reopen ledger");
    let replay = reopened.record(grant("apv:1")).expect("replay");
    assert_eq!(replay.disposition, ApprovalDisposition::AlreadyRecorded);
    assert_eq!(replay.entry_id, first.entry_id);
    assert_eq!(reopened.decision_count().expect("count"), 1);
}

#[test]
fn a_replay_with_a_later_clock_is_still_a_replay_and_keeps_the_first_instant() {
    let (_private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("first recording");

    let mut retry = grant("apv:1");
    retry.decided_at_ms = 9_999;
    let replay = ledger.record(retry).expect("replay");
    assert_eq!(replay.disposition, ApprovalDisposition::AlreadyRecorded);
    // The receipt reports the durable instant, not the one this call carried.
    assert_eq!(replay.decided_at_ms, 1_000);

    let entry = ledger
        .entry("apv:1")
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.decided_at_ms, 1_000);
    assert_eq!(ledger.decision_count().expect("count"), 1);
}

#[test]
fn a_key_presented_with_another_subject_conflicts_and_writes_nothing() {
    let (_private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("first recording");
    let before = snapshot(&ledger, "apv:1");

    let error = ledger
        .record(decided(
            "apv:1",
            "cmd:automonique.admin.rotate",
            ApprovalDecision::Granted,
            "ops:ada",
        ))
        .expect_err("conflict");
    assert_eq!(error.category(), "conflict");
    assert!(
        error.to_string().contains("subject differs"),
        "conflict named the wrong field: {error}"
    );
    assert!(error.to_string().contains("cmd:automonique.admin.shutdown"));

    assert_eq!(snapshot(&ledger, "apv:1"), before);
    assert_eq!(ledger.decision_count().expect("count"), 1);
}

#[test]
fn a_key_presented_with_another_decision_conflicts_and_writes_nothing() {
    let (_private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("first recording");
    let before = snapshot(&ledger, "apv:1");

    // A reversal is a new key, never an edit: this is the refusal that makes a
    // recorded denial impossible to launder into a grant.
    let error = ledger
        .record(decided(
            "apv:1",
            "cmd:automonique.admin.shutdown",
            ApprovalDecision::Denied,
            "ops:ada",
        ))
        .expect_err("conflict");
    assert_eq!(error.category(), "conflict");
    assert!(
        error.to_string().contains("decision differs"),
        "conflict named the wrong field: {error}"
    );
    assert!(error.to_string().contains("granted"));

    assert_eq!(snapshot(&ledger, "apv:1"), before);
    assert_eq!(
        ledger
            .entry("apv:1")
            .expect("read entry")
            .expect("entry present")
            .decision,
        ApprovalDecision::Granted
    );
    assert_eq!(ledger.decision_count().expect("count"), 1);
}

#[test]
fn a_key_presented_with_another_decider_conflicts_and_writes_nothing() {
    let (_private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("first recording");
    let before = snapshot(&ledger, "apv:1");

    let error = ledger
        .record(decided(
            "apv:1",
            "cmd:automonique.admin.shutdown",
            ApprovalDecision::Granted,
            "ops:grace",
        ))
        .expect_err("conflict");
    assert_eq!(error.category(), "conflict");
    assert!(
        error.to_string().contains("decider differs"),
        "conflict named the wrong field: {error}"
    );
    assert!(error.to_string().contains("ops:ada"));

    assert_eq!(snapshot(&ledger, "apv:1"), before);
    assert_eq!(ledger.decision_count().expect("count"), 1);
}

#[test]
fn a_conflict_names_the_first_differing_field_when_several_differ() {
    let (_private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("first recording");

    // Subject, decision and decider all differ; the answer names one field
    // rather than a set, and it is the first in declaration order.
    let error = ledger
        .record(decided(
            "apv:1",
            "effect:deploy:production",
            ApprovalDecision::Denied,
            "ops:grace",
        ))
        .expect_err("conflict");
    assert_eq!(error.category(), "conflict");
    assert!(
        error.to_string().contains("subject differs"),
        "conflict named the wrong field: {error}"
    );
}

#[test]
fn a_conflict_survives_a_restart() {
    let private = PrivateLedger::new();
    {
        let mut ledger = ApprovalLedger::open(private.path()).expect("open ledger");
        ledger.record(grant("apv:1")).expect("first recording");
    }

    let mut reopened = ApprovalLedger::open(private.path()).expect("reopen ledger");
    let error = reopened
        .record(decided(
            "apv:1",
            "cmd:automonique.admin.shutdown",
            ApprovalDecision::Denied,
            "ops:ada",
        ))
        .expect_err("conflict");
    assert_eq!(error.category(), "conflict");
    assert_eq!(reopened.decision_count().expect("count"), 1);
}

#[test]
fn a_reversal_is_a_second_row_under_a_new_key() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(decided(
            "apv:grant",
            "effect:deploy:production",
            ApprovalDecision::Granted,
            "ops:ada",
        ))
        .expect("grant");
    ledger
        .record(decided(
            "apv:revoke",
            "effect:deploy:production",
            ApprovalDecision::Denied,
            "ops:grace",
        ))
        .expect("denial");

    // Both survive. The earlier grant is still evidence that it was made.
    let page = ledger
        .by_subject("effect:deploy:production", 0, 10)
        .expect("subject page");
    assert_eq!(keys(&page.entries), vec!["apv:grant", "apv:revoke"]);
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.decision)
            .collect::<Vec<_>>(),
        vec![ApprovalDecision::Granted, ApprovalDecision::Denied]
    );
    assert_eq!(ledger.decision_count().expect("count"), 2);
}

// ---------------------------------------------------------------------------
// Grammar
// ---------------------------------------------------------------------------

#[test]
fn an_empty_or_malformed_field_is_refused_by_name() {
    let (_private, mut ledger) = ledger();
    let over_long = "k".repeat(MAX_IDENTIFIER_BYTES + 1);

    let cases: [(&str, ApprovalDecisionRecord<'_>); 9] = [
        (
            "approval_key",
            decided("", "subject:x", ApprovalDecision::Granted, "ops:ada"),
        ),
        (
            "approval_key",
            decided(
                "bad\nkey",
                "subject:x",
                ApprovalDecision::Granted,
                "ops:ada",
            ),
        ),
        (
            "approval_key",
            decided(
                over_long.as_str(),
                "subject:x",
                ApprovalDecision::Granted,
                "ops:ada",
            ),
        ),
        (
            "subject",
            decided("apv:x", "", ApprovalDecision::Granted, "ops:ada"),
        ),
        (
            "subject",
            decided(
                "apv:x",
                "bad\tsubject",
                ApprovalDecision::Granted,
                "ops:ada",
            ),
        ),
        (
            "subject",
            decided(
                "apv:x",
                over_long.as_str(),
                ApprovalDecision::Granted,
                "ops:ada",
            ),
        ),
        (
            "decider",
            decided("apv:x", "subject:x", ApprovalDecision::Granted, ""),
        ),
        (
            "decider",
            decided(
                "apv:x",
                "subject:x",
                ApprovalDecision::Granted,
                "bad\rdecider",
            ),
        ),
        (
            "decider",
            decided(
                "apv:x",
                "subject:x",
                ApprovalDecision::Granted,
                over_long.as_str(),
            ),
        ),
    ];

    for (field, record) in cases {
        let error = ledger.record(record).expect_err("grammar refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(
            error.to_string().contains(field),
            "expected {field} to be named, got {error}"
        );
    }
    // Nothing malformed reached the table.
    assert_eq!(ledger.decision_count().expect("count"), 0);
}

#[test]
fn an_identifier_at_the_byte_bound_is_accepted() {
    let (_private, mut ledger) = ledger();
    let at_bound = "k".repeat(MAX_IDENTIFIER_BYTES);
    ledger
        .record(decided(
            at_bound.as_str(),
            at_bound.as_str(),
            ApprovalDecision::Granted,
            at_bound.as_str(),
        ))
        .expect("the bound itself is inside the grammar");
    assert_eq!(ledger.decision_count().expect("count"), 1);
}

#[test]
fn a_negative_decision_instant_is_refused() {
    let (_private, mut ledger) = ledger();
    let mut record = grant("apv:1");
    record.decided_at_ms = -1;
    let error = ledger.record(record).expect_err("time refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("decided_at_ms"));
    assert_eq!(ledger.decision_count().expect("count"), 0);
}

#[test]
fn a_malformed_key_is_refused_on_read_too() {
    let (_private, ledger) = ledger();
    for bad in ["", "bad\nkey"] {
        let error = ledger.entry(bad).expect_err("grammar refusal");
        assert_eq!(error.category(), "invalid_field");
    }
    let error = ledger
        .by_subject("bad\nsubject", 0, 10)
        .expect_err("grammar refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("subject"));
}

// ---------------------------------------------------------------------------
// Reads and pagination
// ---------------------------------------------------------------------------

/// Six decisions over three subjects, interleaved so a subject page cannot pass
/// by returning a contiguous run.
fn populated() -> (PrivateLedger, ApprovalLedger) {
    let (private, mut ledger) = ledger();
    for (key, subject, decision) in [
        ("apv:1", "cmd:shutdown", ApprovalDecision::Granted),
        ("apv:2", "effect:deploy", ApprovalDecision::Denied),
        ("apv:3", "cmd:shutdown", ApprovalDecision::Denied),
        ("apv:4", "tool:write", ApprovalDecision::Granted),
        ("apv:5", "effect:deploy", ApprovalDecision::Granted),
        ("apv:6", "cmd:shutdown", ApprovalDecision::Granted),
    ] {
        ledger
            .record(decided(key, subject, decision, "ops:ada"))
            .expect("record");
    }
    (private, ledger)
}

#[test]
fn a_subject_page_carries_exactly_the_matching_rows_in_order() {
    let (_private, ledger) = populated();

    let page = ledger
        .by_subject("cmd:shutdown", 0, 10)
        .expect("subject page");
    assert_eq!(keys(&page.entries), vec!["apv:1", "apv:3", "apv:6"]);
    assert_eq!(page.next_cursor, None);
    for entry in &page.entries {
        assert_eq!(entry.subject, "cmd:shutdown");
    }

    let other = ledger
        .by_subject("effect:deploy", 0, 10)
        .expect("subject page");
    assert_eq!(keys(&other.entries), vec!["apv:2", "apv:5"]);

    let absent = ledger
        .by_subject("subject:none", 0, 10)
        .expect("subject page");
    assert!(absent.entries.is_empty());
    assert_eq!(absent.next_cursor, None);
}

#[test]
fn a_subject_page_is_bounded_and_resumes_from_its_cursor() {
    let (_private, ledger) = populated();

    let first = ledger
        .by_subject("cmd:shutdown", 0, 2)
        .expect("subject page");
    assert_eq!(keys(&first.entries), vec!["apv:1", "apv:3"]);
    let cursor = first.next_cursor.expect("a further row was seen");

    let second = ledger
        .by_subject("cmd:shutdown", cursor, 2)
        .expect("subject page");
    assert_eq!(keys(&second.entries), vec!["apv:6"]);
    // Exhausted, not merely filled.
    assert_eq!(second.next_cursor, None);
}

#[test]
fn a_page_over_everything_is_bounded_and_resumes_from_its_cursor() {
    let (_private, ledger) = populated();

    let first = ledger.page(0, 4).expect("page");
    assert_eq!(
        keys(&first.entries),
        vec!["apv:1", "apv:2", "apv:3", "apv:4"]
    );
    let cursor = first.next_cursor.expect("a further row was seen");

    let second = ledger.page(cursor, 4).expect("page");
    assert_eq!(keys(&second.entries), vec!["apv:5", "apv:6"]);
    assert_eq!(second.next_cursor, None);
}

#[test]
fn a_cursor_above_the_retained_window_is_refused() {
    let (_private, ledger) = populated();
    let range = ledger.retained_range().expect("range").expect("non-empty");

    // An empty page and a lost cursor are different answers.
    let exhausted = ledger.page(range.last, 4).expect("page at the last row");
    assert!(exhausted.entries.is_empty());

    let error = ledger.page(range.last + 1, 4).expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
    let error = ledger
        .by_subject("cmd:shutdown", range.last + 1, 4)
        .expect_err("cursor refusal");
    assert_eq!(error.category(), "cursor_out_of_range");
}

#[test]
fn a_subject_page_judges_its_cursor_against_the_whole_ledger() {
    let (_private, ledger) = populated();

    // `apv:6` is the highest row and belongs to `cmd:shutdown`, so a cursor
    // above every `effect:deploy` row is still a position in the listing order
    // rather than a lost cursor.
    let page = ledger
        .by_subject("effect:deploy", 5, 4)
        .expect("subject page");
    assert!(page.entries.is_empty());
    assert_eq!(page.next_cursor, None);
}

#[test]
fn a_limit_outside_its_bounds_is_refused() {
    let (_private, ledger) = populated();
    for limit in [0, MAX_APPROVAL_PAGE + 1] {
        let error = ledger.page(0, limit).expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("limit"));
        let error = ledger
            .by_subject("cmd:shutdown", 0, limit)
            .expect_err("limit refusal");
        assert_eq!(error.category(), "invalid_field");
    }
}

#[test]
fn the_retained_window_grows_with_every_recording() {
    let (_private, mut ledger) = ledger();
    assert_eq!(ledger.retained_range().expect("range"), None);

    for index in 1..=4u64 {
        ledger
            .record(grant(&format!("apv:{index}")))
            .expect("record");
        let range = ledger.retained_range().expect("range").expect("non-empty");
        // Nothing prunes, so the floor never moves.
        assert_eq!(range.first, 1);
        assert_eq!(range.last, index);
        assert_eq!(ledger.decision_count().expect("count"), index as usize);
    }

    // A replay moves neither bound.
    ledger.record(grant("apv:4")).expect("replay");
    let range = ledger.retained_range().expect("range").expect("non-empty");
    assert_eq!((range.first, range.last), (1, 4));
    assert_eq!(ledger.decision_count().expect("count"), 4);
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[test]
fn every_recorded_decision_survives_close_and_reopen() {
    let private = PrivateLedger::new();
    {
        let mut ledger = ApprovalLedger::open(private.path()).expect("open ledger");
        ledger
            .record(decided(
                "apv:1",
                "cmd:shutdown",
                ApprovalDecision::Granted,
                "ops:ada",
            ))
            .expect("grant");
        ledger
            .record(decided(
                "apv:2",
                "cmd:shutdown",
                ApprovalDecision::Denied,
                "ops:grace",
            ))
            .expect("denial");
    }

    let reopened = ApprovalLedger::open(private.path()).expect("reopen ledger");
    let page = reopened.page(0, 10).expect("page");
    assert_eq!(keys(&page.entries), vec!["apv:1", "apv:2"]);
    assert_eq!(page.entries[0].decision, ApprovalDecision::Granted);
    assert_eq!(page.entries[0].decider, "ops:ada");
    assert_eq!(page.entries[1].decision, ApprovalDecision::Denied);
    assert_eq!(page.entries[1].decider, "ops:grace");
    assert_eq!(
        reopened
            .retained_range()
            .expect("range")
            .expect("non-empty"),
        RetainedApprovalRange { first: 1, last: 2 }
    );
}

// ---------------------------------------------------------------------------
// Corruption on read
// ---------------------------------------------------------------------------

#[test]
fn a_hand_written_unknown_decision_surfaces_as_corruption() {
    let (private, mut ledger) = ledger();
    ledger
        .record(decided(
            "apv:1",
            "cmd:shutdown",
            ApprovalDecision::Granted,
            "ops:ada",
        ))
        .expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE approval_decisions SET decision = 'maybe' WHERE approval_key = 'apv:1'",
        [],
    )
    .expect_err("the column CHECK refuses a decision outside the vocabulary");

    // A writer that disabled constraint enforcement gets the row in anyway.
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE approval_decisions SET decision = 'maybe' WHERE approval_key = 'apv:1'",
        [],
    )
    .expect("smuggle decision");
    drop(raw);

    // Every read path refuses it rather than guessing what 'maybe' meant. In
    // particular nothing treats an unrecognised decision as "not granted".
    let reopened = ApprovalLedger::open(private.path()).expect("reopen");
    let error = reopened.entry("apv:1").expect_err("vocabulary refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("decision"));
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
    // The subject filter selects the row, so it cannot hide the corruption.
    assert_eq!(
        reopened
            .by_subject("cmd:shutdown", 0, 10)
            .expect_err("subject page refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_second_revision_surfaces_as_corruption() {
    let (private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE approval_decisions SET revision = 2 WHERE approval_key = 'apv:1'",
        [],
    )
    .expect_err("the column CHECK pins write-once rows to one revision");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE approval_decisions SET decision = 'denied', revision = 2
         WHERE approval_key = 'apv:1'",
        [],
    )
    .expect("smuggle an amended decision");
    drop(raw);

    // An amended row is not an amended decision: this API writes revision one
    // and only revision one, so a second revision is a second writer's work.
    let reopened = ApprovalLedger::open(private.path()).expect("reopen");
    let error = reopened.entry("apv:1").expect_err("revision refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("revision"));
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_control_character_decider_surfaces_as_corruption() {
    let (private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE approval_decisions SET decider = ?1 WHERE approval_key = 'apv:1'",
        params!["ops:\u{7}ada"],
    )
    .expect("smuggle decider");
    drop(raw);

    let reopened = ApprovalLedger::open(private.path()).expect("reopen");
    let error = reopened
        .entry("apv:1")
        .expect_err("grammar refusal on read");
    // A bad stored row is corruption, never the caller's InvalidField.
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("decider"));
}

#[test]
fn a_hand_written_empty_subject_surfaces_as_corruption() {
    let (private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE approval_decisions SET subject = '' WHERE approval_key = 'apv:1'",
        [],
    )
    .expect("smuggle subject");
    drop(raw);

    let reopened = ApprovalLedger::open(private.path()).expect("reopen");
    let error = reopened
        .entry("apv:1")
        .expect_err("grammar refusal on read");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("subject"));
    // The unfiltered listing is the one that must see every row, and it does.
    assert_eq!(
        reopened.page(0, 10).expect_err("page refusal").category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_non_positive_identity_surfaces_as_corruption() {
    let (private, ledger) = ledger();
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO approval_decisions
         (entry_id, approval_key, subject, decision, decider, decided_at_ms, revision)
         VALUES (0, 'apv:0', 'cmd:shutdown', 'granted', 'ops:ada', 1000, 1)",
        [],
    )
    .expect("smuggle a zero identity");
    drop(raw);

    let reopened = ApprovalLedger::open(private.path()).expect("reopen");
    let error = reopened.entry("apv:0").expect_err("identity refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("entry_id"));
    // The retained window is derived from the same column and refuses too,
    // rather than reporting a floor no writer produced.
    assert_eq!(
        reopened
            .retained_range()
            .expect_err("range refusal")
            .category(),
        "corrupt"
    );
}

#[test]
fn a_hand_written_negative_instant_surfaces_as_corruption() {
    let (private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE approval_decisions SET decided_at_ms = -1 WHERE approval_key = 'apv:1'",
        [],
    )
    .expect("smuggle instant");
    drop(raw);

    let reopened = ApprovalLedger::open(private.path()).expect("reopen");
    let error = reopened.entry("apv:1").expect_err("time refusal on read");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("decided_at_ms"));
}

#[test]
fn a_corrupt_row_is_refused_on_the_record_path_too() {
    let (private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.pragma_update(None, "ignore_check_constraints", true)
        .expect("disable checks");
    raw.execute(
        "UPDATE approval_decisions SET decision = 'maybe' WHERE approval_key = 'apv:1'",
        [],
    )
    .expect("smuggle decision");
    drop(raw);

    // The replay comparison reads the durable row first, and refuses a row it
    // cannot have written rather than treating it as a conflict or a replay.
    let mut reopened = ApprovalLedger::open(private.path()).expect("reopen");
    let error = reopened.record(grant("apv:1")).expect_err("corruption");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("decision"));
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_refuses_to_grow_past_its_capacity() {
    let private = PrivateLedger::new();
    let mut ledger = ApprovalLedger::open_with_capacity(private.path(), 2).expect("open ledger");
    assert_eq!(ledger.capacity(), 2);
    ledger.record(grant("apv:1")).expect("first");
    ledger.record(grant("apv:2")).expect("second");

    let error = ledger.record(grant("apv:3")).expect_err("capacity refusal");
    assert_eq!(error.category(), "ledger_full");
    assert!(error.to_string().contains('2'));
    // Refusal, never eviction: the ledger has no prune, so a full ledger stays
    // full and the decisions it holds are exactly the ones it started with.
    assert_eq!(ledger.decision_count().expect("count"), 2);
    assert_eq!(
        keys(&ledger.page(0, 10).expect("page").entries),
        vec!["apv:1", "apv:2"]
    );
}

#[test]
fn a_full_ledger_still_replays_and_still_reads() {
    let private = PrivateLedger::new();
    let mut ledger = ApprovalLedger::open_with_capacity(private.path(), 1).expect("open ledger");
    let first = ledger.record(grant("apv:1")).expect("first");

    // A replay writes nothing, so it must never degrade into a refusal.
    let replay = ledger
        .record(grant("apv:1"))
        .expect("replay in a full ledger");
    assert_eq!(replay.disposition, ApprovalDisposition::AlreadyRecorded);
    assert_eq!(replay.entry_id, first.entry_id);

    // And a conflicting reuse is a caller bug regardless of how full the ledger
    // is, so it is reported as one.
    let error = ledger
        .record(decided(
            "apv:1",
            "cmd:automonique.admin.shutdown",
            ApprovalDecision::Denied,
            "ops:ada",
        ))
        .expect_err("conflict, not ledger_full");
    assert_eq!(error.category(), "conflict");

    // Only a genuinely new decision is refused for room.
    assert_eq!(
        ledger
            .record(grant("apv:2"))
            .expect_err("capacity refusal")
            .category(),
        "ledger_full"
    );

    assert!(ledger.entry("apv:1").expect("read entry").is_some());
    assert_eq!(ledger.decision_count().expect("count"), 1);
}

#[test]
fn a_lowered_capacity_below_the_row_count_still_reads_and_replays() {
    let private = PrivateLedger::new();
    {
        let mut ledger = ApprovalLedger::open(private.path()).expect("open ledger");
        ledger.record(grant("apv:1")).expect("first");
        ledger.record(grant("apv:2")).expect("second");
    }

    let mut narrowed = ApprovalLedger::open_with_capacity(private.path(), 1).expect("reopen");
    assert_eq!(narrowed.decision_count().expect("count"), 2);
    assert_eq!(
        narrowed.record(grant("apv:2")).expect("replay").disposition,
        ApprovalDisposition::AlreadyRecorded
    );
    assert_eq!(
        narrowed
            .record(grant("apv:3"))
            .expect_err("capacity refusal")
            .category(),
        "ledger_full"
    );
    assert_eq!(
        keys(&narrowed.page(0, 10).expect("page").entries),
        vec!["apv:1", "apv:2"]
    );
}

// ---------------------------------------------------------------------------
// Anti-drift
// ---------------------------------------------------------------------------

/// The two spellings are the approval-decision contract, pinned by literal.
///
/// The pin is a literal one and the reason is stated rather than assumed: this
/// crate does not depend on `automonique-protocol` — its dependencies are `nix`
/// and `rusqlite` — and the protocol has no approval *decision* type to derive
/// from in any case. Its approval vocabulary is a policy
/// (`command_registry::ApprovalPolicy::{None, OperatorConfirmation}`) and a pair
/// of two-valued outcomes (`automation::UnattendedDecision`,
/// `automation::ActionBinding`) that say whether an approval is *needed*, never
/// what a human answered. What the protocol does pin is the refusal word:
/// `sandbox::NetworkAccess::Denied` and
/// `connector_conformance::DispositionOutcome::Denied` both render `denied`.
#[test]
fn the_two_decision_spellings_are_granted_and_denied() {
    assert_eq!(
        ApprovalDecision::ALL
            .iter()
            .map(|decision| decision.as_str())
            .collect::<Vec<_>>(),
        vec!["granted", "denied"]
    );

    for decision in ApprovalDecision::ALL {
        assert_eq!(
            ApprovalDecision::from_spelling(decision.as_str()),
            Some(decision)
        );
        assert_eq!(decision.to_string(), decision.as_str());
    }
    assert_eq!(ApprovalDecision::from_spelling("GRANTED"), None);
    assert_eq!(ApprovalDecision::from_spelling("approved"), None);
    assert_eq!(ApprovalDecision::from_spelling("rejected"), None);
    assert_eq!(ApprovalDecision::from_spelling("pending"), None);
    assert_eq!(ApprovalDecision::from_spelling(""), None);

    // Exactly one of the two grants.
    assert!(ApprovalDecision::Granted.grants());
    assert!(!ApprovalDecision::Denied.grants());
}

/// The sibling that already records approvals must spell them the same way.
///
/// `provider_journal::ApprovalDecision` writes the identical
/// `CHECK (decision IN ('granted', 'denied'))` column for the per-session
/// binding, and the daemon writes both tables for the same human answer. Its
/// renderer and parser are module-private, so this pin is on the variant names
/// — the strongest link available without widening that module's surface. A
/// rename there fails here.
#[test]
fn the_spellings_agree_with_the_provider_journal_binding() {
    for (ours, journal) in [
        (ApprovalDecision::Granted, JournalDecision::Granted),
        (ApprovalDecision::Denied, JournalDecision::Denied),
    ] {
        assert_eq!(
            ours.as_str(),
            format!("{journal:?}").to_lowercase(),
            "the two approval decision vocabularies drifted apart"
        );
    }
}

/// The stored column admits exactly the two spellings and nothing else.
#[test]
fn the_stored_vocabulary_is_closed_to_anything_else() {
    let (private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    for spelling in ["", "GRANTED", "approved", "rejected", "maybe", "pending"] {
        raw.execute(
            "UPDATE approval_decisions SET decision = ?1 WHERE approval_key = 'apv:1'",
            params![spelling],
        )
        .expect_err("the column refuses a spelling outside the vocabulary");
    }
    for decision in ApprovalDecision::ALL {
        raw.execute(
            "UPDATE approval_decisions SET decision = ?1 WHERE approval_key = 'apv:1'",
            params![decision.as_str()],
        )
        .expect("the column admits every spelling this build defines");
    }
}

/// Write-once is a property of the table, not only of the write path.
#[test]
fn the_stored_revision_is_pinned_to_one() {
    let (private, mut ledger) = ledger();
    ledger.record(grant("apv:1")).expect("record");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    for revision in [0, 2, -1] {
        raw.execute(
            "UPDATE approval_decisions SET revision = ?1 WHERE approval_key = 'apv:1'",
            params![revision],
        )
        .expect_err("the column CHECK admits exactly one revision");
    }

    // And the unique key is a database constraint, so a second writer cannot
    // introduce a duplicate custody record for one approval.
    raw.execute(
        "INSERT INTO approval_decisions
         (approval_key, subject, decision, decider, decided_at_ms, revision)
         VALUES ('apv:1', 'other', 'denied', 'ops:grace', 2000, 1)",
        [],
    )
    .expect_err("approval_key is unique");
}

#[test]
fn the_schema_version_this_module_owns_is_stable() {
    // A bump here is a migration decision, not an implementation detail.
    assert_eq!(APPROVAL_LEDGER_SCHEMA_VERSION, 1);
}
