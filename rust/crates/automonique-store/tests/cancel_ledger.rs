// SPDX-License-Identifier: Elastic-2.0

//! Durable cancellation ledger invariants.
//!
//! Every refusal here is asserted by stable category, not by message text, so a
//! mutation that reaches a different guard fails the test instead of passing
//! through a neighbouring refusal. The restart tests close the ledger and
//! reopen the file: an in-memory ledger cannot pass them, which is the whole
//! reason this module exists.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use automonique_store::cancel_ledger::{
    CANCEL_LEDGER_SCHEMA_VERSION, CancelDisposition, CancelLedger, CancelRequest,
    MAX_IDENTIFIER_BYTES, MAX_LEDGER_ENTRIES, Retention,
};
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
        let path = directory.path().join("cancel-ledger.sqlite3");
        Self {
            _directory: directory,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn ledger() -> (PrivateLedger, CancelLedger) {
    let private = PrivateLedger::new();
    let opened = CancelLedger::open(private.path()).expect("open ledger");
    (private, opened)
}

fn request<'a>(
    request_ref: &'a str,
    attempt_id: &'a str,
    observed_sequence: u64,
) -> CancelRequest<'a> {
    CancelRequest {
        request_ref,
        attempt_id,
        observed_sequence,
        requested_at_ms: 1_000,
    }
}

#[test]
fn a_fresh_ledger_stamps_its_schema_version() {
    let (private, ledger) = ledger();
    assert_eq!(ledger.path(), private.path());
    assert_eq!(ledger.capacity(), MAX_LEDGER_ENTRIES);
    assert_eq!(ledger.entry_count().expect("count"), 0);
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw reopen");
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, CANCEL_LEDGER_SCHEMA_VERSION);
}

#[test]
fn a_foreign_schema_version_is_refused() {
    let (private, ledger) = ledger();
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw reopen");
    raw.pragma_update(None, "user_version", 9_999u32)
        .expect("stamp foreign version");
    drop(raw);

    let error = CancelLedger::open(private.path()).expect_err("schema refusal");
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
    // ledger refuses it rather than creating its tables alongside them.
    let error = CancelLedger::open(private.path()).expect_err("schema refusal");
    assert_eq!(error.category(), "schema_version");
}

#[test]
fn a_group_readable_ledger_file_is_refused() {
    let (private, ledger) = ledger();
    drop(ledger);
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o640))
        .expect("loosen file mode");

    let error = CancelLedger::open(private.path()).expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_world_readable_directory_is_refused() {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
        .expect("loose permissions");
    let error = CancelLedger::open(directory.path().join("cancel-ledger.sqlite3"))
        .expect_err("privacy refusal");
    assert_eq!(error.category(), "insecure_path");
}

#[test]
fn a_first_delivery_is_recorded_and_an_exact_replay_is_not() {
    let (_private, mut ledger) = ledger();

    let first = ledger
        .record(request("ref:a", "attempt:a", 7))
        .expect("first delivery");
    assert_eq!(first.disposition, CancelDisposition::Delivered);
    assert_eq!(first.disposition.as_str(), "delivered");

    let replay = ledger
        .record(request("ref:a", "attempt:a", 7))
        .expect("exact replay");
    assert_eq!(replay.disposition, CancelDisposition::AlreadyDelivered);
    assert_eq!(replay.disposition.as_str(), "already_delivered");
    assert_eq!(replay.entry_id, first.entry_id);
    assert_eq!(ledger.entry_count().expect("count"), 1, "no second row");
}

/// The point of the module: idempotency that outlives the process.
#[test]
fn an_exact_replay_after_close_and_reopen_is_already_delivered() {
    let private = PrivateLedger::new();

    let mut ledger = CancelLedger::open(private.path()).expect("open ledger");
    let first = ledger
        .record(request("ref:restart", "attempt:a", 12))
        .expect("first delivery");
    assert_eq!(first.disposition, CancelDisposition::Delivered);
    drop(ledger);

    let mut reopened = CancelLedger::open(private.path()).expect("reopen ledger");
    let replay = reopened
        .record(request("ref:restart", "attempt:a", 12))
        .expect("replay after restart");
    assert_eq!(replay.disposition, CancelDisposition::AlreadyDelivered);
    assert_eq!(replay.entry_id, first.entry_id);
    assert_eq!(reopened.entry_count().expect("count"), 1);

    // And the row itself survived intact, not merely its key.
    let entry = reopened
        .entry("ref:restart")
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.attempt_id, "attempt:a");
    assert_eq!(entry.observed_sequence, 12);
    assert_eq!(entry.requested_at_ms, 1_000);
}

#[test]
fn a_replay_with_a_later_timestamp_is_still_an_exact_replay() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(request("ref:a", "attempt:a", 3))
        .expect("first delivery");

    let receipt = ledger
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:a",
            observed_sequence: 3,
            requested_at_ms: 9_999,
        })
        .expect("retry with a later clock");
    assert_eq!(receipt.disposition, CancelDisposition::AlreadyDelivered);

    // The recorded instant is the first delivery's, never rewritten.
    let entry = ledger
        .entry("ref:a")
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.requested_at_ms, 1_000);
}

#[test]
fn a_reference_reused_for_another_attempt_conflicts_and_writes_nothing() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(request("ref:a", "attempt:a", 5))
        .expect("first delivery");

    let error = ledger
        .record(request("ref:a", "attempt:b", 5))
        .expect_err("attempt conflict");
    assert_eq!(error.category(), "conflict");
    assert!(error.to_string().contains("attempt_id differs"));

    // The durable binding is untouched: no overwrite hid behind the refusal.
    let entry = ledger
        .entry("ref:a")
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.attempt_id, "attempt:a");
    assert_eq!(entry.observed_sequence, 5);
    assert_eq!(ledger.entry_count().expect("count"), 1);
    assert!(
        ledger
            .attempt_requests("attempt:b")
            .expect("recovery view")
            .is_empty(),
        "a conflicting attempt must own no entry"
    );
}

#[test]
fn a_reference_reused_at_another_sequence_conflicts_and_writes_nothing() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(request("ref:a", "attempt:a", 5))
        .expect("first delivery");

    let error = ledger
        .record(request("ref:a", "attempt:a", 6))
        .expect_err("sequence conflict");
    assert_eq!(error.category(), "conflict");
    assert!(error.to_string().contains("observed_sequence differs"));

    let entry = ledger
        .entry("ref:a")
        .expect("read entry")
        .expect("entry present");
    assert_eq!(entry.observed_sequence, 5);
    assert_eq!(ledger.entry_count().expect("count"), 1);
}

/// A behind sequence is as much a conflict as an ahead one: the ledger compares
/// the binding, it does not rank sequences.
#[test]
fn a_behind_sequence_conflicts_too() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(request("ref:a", "attempt:a", 5))
        .expect("first delivery");
    let error = ledger
        .record(request("ref:a", "attempt:a", 4))
        .expect_err("behind sequence conflict");
    assert_eq!(error.category(), "conflict");
}

#[test]
fn a_conflict_survives_a_restart() {
    let private = PrivateLedger::new();
    let mut ledger = CancelLedger::open(private.path()).expect("open ledger");
    ledger
        .record(request("ref:a", "attempt:a", 5))
        .expect("first delivery");
    drop(ledger);

    let mut reopened = CancelLedger::open(private.path()).expect("reopen ledger");
    let error = reopened
        .record(request("ref:a", "attempt:a", 6))
        .expect_err("conflict after restart");
    assert_eq!(error.category(), "conflict");
    assert_eq!(reopened.entry_count().expect("count"), 1);
}

#[test]
fn distinct_references_for_one_attempt_are_all_recorded() {
    let (_private, mut ledger) = ledger();
    for (index, request_ref) in ["ref:a", "ref:b", "ref:c"].iter().enumerate() {
        let receipt = ledger
            .record(request(request_ref, "attempt:a", index as u64))
            .expect("delivery");
        assert_eq!(receipt.disposition, CancelDisposition::Delivered);
    }
    let entries = ledger.attempt_requests("attempt:a").expect("recovery view");
    let refs: Vec<&str> = entries
        .iter()
        .map(|entry| entry.request_ref.as_str())
        .collect();
    assert_eq!(refs, vec!["ref:a", "ref:b", "ref:c"], "oldest first");
    assert_eq!(entries[2].observed_sequence, 2);
}

#[test]
fn the_recovery_view_is_scoped_to_one_attempt_and_survives_a_restart() {
    let private = PrivateLedger::new();
    let mut ledger = CancelLedger::open(private.path()).expect("open ledger");
    ledger
        .record(request("ref:a", "attempt:a", 1))
        .expect("delivery a");
    ledger
        .record(request("ref:b", "attempt:b", 2))
        .expect("delivery b");
    drop(ledger);

    let reopened = CancelLedger::open(private.path()).expect("reopen ledger");
    let entries = reopened
        .attempt_requests("attempt:a")
        .expect("recovery view");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].request_ref, "ref:a");
    assert!(
        reopened
            .attempt_requests("attempt:unknown")
            .expect("recovery view")
            .is_empty()
    );
    assert!(reopened.entry("ref:missing").expect("lookup").is_none());
}

#[test]
fn a_refused_batch_leaves_none_of_its_earlier_rows_behind() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(request("ref:existing", "attempt:a", 5))
        .expect("pre-existing entry");

    // The third request conflicts with the pre-existing binding; the first two
    // are perfectly valid and must not survive the refusal.
    let error = ledger
        .record_all(&[
            request("ref:one", "attempt:a", 1),
            request("ref:two", "attempt:a", 2),
            request("ref:existing", "attempt:a", 99),
        ])
        .expect_err("batch conflict");
    assert_eq!(error.category(), "conflict");

    assert!(ledger.entry("ref:one").expect("lookup").is_none());
    assert!(ledger.entry("ref:two").expect("lookup").is_none());
    assert_eq!(ledger.entry_count().expect("count"), 1);
    assert_eq!(
        ledger
            .entry("ref:existing")
            .expect("lookup")
            .expect("entry present")
            .observed_sequence,
        5
    );
}

#[test]
fn a_batch_refused_at_the_capacity_boundary_writes_nothing() {
    let private = PrivateLedger::new();
    let mut ledger =
        CancelLedger::open_with_capacity(private.path(), 3).expect("open bounded ledger");
    ledger
        .record(request("ref:existing", "attempt:a", 0))
        .expect("first entry");

    // Two more fit; the third crosses the cap mid-transaction.
    let error = ledger
        .record_all(&[
            request("ref:one", "attempt:a", 1),
            request("ref:two", "attempt:a", 2),
            request("ref:three", "attempt:a", 3),
        ])
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "ledger_full");

    assert_eq!(ledger.entry_count().expect("count"), 1);
    assert!(ledger.entry("ref:one").expect("lookup").is_none());
    assert!(ledger.entry("ref:two").expect("lookup").is_none());
}

#[test]
fn a_committed_batch_records_every_request() {
    let (_private, mut ledger) = ledger();
    let receipts = ledger
        .record_all(&[
            request("ref:one", "attempt:a", 1),
            request("ref:two", "attempt:a", 2),
        ])
        .expect("batch delivery");
    assert_eq!(receipts.len(), 2);
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.disposition == CancelDisposition::Delivered)
    );
    assert_eq!(ledger.entry_count().expect("count"), 2);
}

#[test]
fn a_repeat_inside_one_batch_sees_the_row_that_batch_just_wrote() {
    let (_private, mut ledger) = ledger();
    let receipts = ledger
        .record_all(&[
            request("ref:a", "attempt:a", 4),
            request("ref:a", "attempt:a", 4),
        ])
        .expect("batch with an exact repeat");
    assert_eq!(receipts[0].disposition, CancelDisposition::Delivered);
    assert_eq!(receipts[1].disposition, CancelDisposition::AlreadyDelivered);
    assert_eq!(receipts[0].entry_id, receipts[1].entry_id);
    assert_eq!(ledger.entry_count().expect("count"), 1);

    let error = ledger
        .record_all(&[
            request("ref:b", "attempt:a", 1),
            request("ref:b", "attempt:a", 2),
        ])
        .expect_err("altered repeat inside a batch");
    assert_eq!(error.category(), "conflict");
    assert!(ledger.entry("ref:b").expect("lookup").is_none());
}

#[test]
fn the_ledger_refuses_to_grow_past_its_capacity() {
    let private = PrivateLedger::new();
    let mut ledger =
        CancelLedger::open_with_capacity(private.path(), 2).expect("open bounded ledger");
    assert_eq!(ledger.capacity(), 2);
    ledger
        .record(request("ref:one", "attempt:a", 1))
        .expect("first entry");
    ledger
        .record(request("ref:two", "attempt:a", 2))
        .expect("second entry");

    let error = ledger
        .record(request("ref:three", "attempt:a", 3))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "ledger_full");
    assert!(error.to_string().contains("capacity of 2"));
    assert_eq!(ledger.entry_count().expect("count"), 2);

    // A full ledger still answers an exact replay: a replay writes nothing.
    let replay = ledger
        .record(request("ref:one", "attempt:a", 1))
        .expect("replay in a full ledger");
    assert_eq!(replay.disposition, CancelDisposition::AlreadyDelivered);

    // And a conflicting reuse is still a conflict, not a capacity refusal.
    let error = ledger
        .record(request("ref:one", "attempt:a", 42))
        .expect_err("conflict in a full ledger");
    assert_eq!(error.category(), "conflict");
}

#[test]
fn a_capacity_outside_its_bounds_is_refused() {
    let private = PrivateLedger::new();
    let error =
        CancelLedger::open_with_capacity(private.path(), 0).expect_err("zero capacity refusal");
    assert_eq!(error.category(), "invalid_field");
    let error = CancelLedger::open_with_capacity(private.path(), MAX_LEDGER_ENTRIES + 1)
        .expect_err("over-large capacity refusal");
    assert_eq!(error.category(), "invalid_field");
}

#[test]
fn identifiers_outside_the_store_grammar_are_refused() {
    let (_private, mut ledger) = ledger();
    let over_long = "r".repeat(MAX_IDENTIFIER_BYTES + 1);
    let at_limit = "r".repeat(MAX_IDENTIFIER_BYTES);

    for bad in ["", "ref\nsmuggled", "ref\0nul", over_long.as_str()] {
        let error = ledger
            .record(request(bad, "attempt:a", 1))
            .expect_err("request_ref grammar refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("request_ref"));

        let error = ledger
            .record(request("ref:a", bad, 1))
            .expect_err("attempt_id grammar refusal");
        assert_eq!(error.category(), "invalid_field");
        assert!(error.to_string().contains("attempt_id"));

        let error = ledger.entry(bad).expect_err("lookup grammar refusal");
        assert_eq!(error.category(), "invalid_field");
        let error = ledger
            .attempt_requests(bad)
            .expect_err("recovery grammar refusal");
        assert_eq!(error.category(), "invalid_field");
    }

    let error = ledger
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:a",
            observed_sequence: 1,
            requested_at_ms: -1,
        })
        .expect_err("negative time refusal");
    assert_eq!(error.category(), "invalid_field");

    let error = ledger
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:a",
            observed_sequence: u64::MAX,
            requested_at_ms: 1,
        })
        .expect_err("unrepresentable sequence refusal");
    assert_eq!(error.category(), "invalid_field");

    assert_eq!(
        ledger.entry_count().expect("count"),
        0,
        "no refused write may have landed"
    );

    // The boundary itself is accepted, so the bound is exactly where it says.
    let receipt = ledger
        .record(request(at_limit.as_str(), "attempt:a", 1))
        .expect("identifier at the limit");
    assert_eq!(receipt.disposition, CancelDisposition::Delivered);
}

#[test]
fn an_over_long_batch_is_refused_before_any_row_is_written() {
    let (_private, mut ledger) = ledger();
    let refs: Vec<String> = (0..=1_024).map(|index| format!("ref:{index}")).collect();
    let batch: Vec<CancelRequest<'_>> = refs
        .iter()
        .map(|request_ref| request(request_ref.as_str(), "attempt:a", 1))
        .collect();

    let error = ledger.record_all(&batch).expect_err("batch bound refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("batch_length"));
    assert_eq!(ledger.entry_count().expect("count"), 0);
}

#[test]
fn a_malformed_request_anywhere_in_a_batch_writes_nothing() {
    let (_private, mut ledger) = ledger();
    let error = ledger
        .record_all(&[
            request("ref:one", "attempt:a", 1),
            request("", "attempt:a", 2),
        ])
        .expect_err("field refusal");
    assert_eq!(error.category(), "invalid_field");
    assert_eq!(ledger.entry_count().expect("count"), 0);
}

#[test]
fn a_hand_written_empty_reference_surfaces_as_corruption() {
    let (private, mut ledger) = ledger();
    ledger
        .record(request("ref:a", "attempt:a", 1))
        .expect("first delivery");
    drop(ledger);

    // A row this API would have refused: the grammar is not a column CHECK.
    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO cancel_requests
         (request_ref, attempt_id, observed_sequence, requested_at_ms)
         VALUES ('', 'attempt:a', 2, 100)",
        [],
    )
    .expect("smuggle empty reference");
    drop(raw);

    let reopened = CancelLedger::open(private.path()).expect("reopen");
    let error = reopened
        .attempt_requests("attempt:a")
        .expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("request_ref"));
}

#[test]
fn a_hand_written_control_character_attempt_surfaces_as_corruption() {
    let (private, mut ledger) = ledger();
    ledger
        .record(request("ref:a", "attempt:a", 1))
        .expect("first delivery");
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "UPDATE cancel_requests SET attempt_id = ?1 WHERE request_ref = 'ref:a'",
        params!["attempt:\u{7}bell"],
    )
    .expect("smuggle control character");
    drop(raw);

    let reopened = CancelLedger::open(private.path()).expect("reopen");
    let error = reopened.entry("ref:a").expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("attempt_id"));
}

#[test]
fn a_hand_written_over_long_reference_surfaces_as_corruption_on_record() {
    let (private, ledger) = ledger();
    drop(ledger);

    let raw = Connection::open(private.path()).expect("raw write");
    raw.execute(
        "INSERT INTO cancel_requests
         (request_ref, attempt_id, observed_sequence, requested_at_ms)
         VALUES (?1, 'attempt:a', 1, 100)",
        params!["r".repeat(MAX_IDENTIFIER_BYTES + 1)],
    )
    .expect("smuggle over-long reference");
    drop(raw);

    // Recording reads before it writes, so corruption stops a write too.
    let mut reopened = CancelLedger::open(private.path()).expect("reopen");
    let error = reopened
        .record(request("ref:new", "attempt:a", 1))
        .expect("an unrelated reference is unaffected")
        .disposition;
    assert_eq!(error, CancelDisposition::Delivered);

    let error = reopened
        .attempt_requests("attempt:a")
        .expect_err("corruption refusal");
    assert_eq!(error.category(), "corrupt");
    assert!(error.to_string().contains("request_ref"));
}

#[test]
fn pruning_removes_only_old_entries_of_terminal_attempts() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(CancelRequest {
            request_ref: "ref:old-terminal",
            attempt_id: "attempt:done",
            observed_sequence: 1,
            requested_at_ms: 100,
        })
        .expect("old terminal entry");
    ledger
        .record(CancelRequest {
            request_ref: "ref:recent-terminal",
            attempt_id: "attempt:done",
            observed_sequence: 2,
            requested_at_ms: 900,
        })
        .expect("recent terminal entry");
    ledger
        .record(CancelRequest {
            request_ref: "ref:old-live",
            attempt_id: "attempt:live",
            observed_sequence: 3,
            requested_at_ms: 100,
        })
        .expect("old live entry");

    let outcome = ledger
        .prune(Retention {
            older_than_ms: 500,
            terminal_attempts: &["attempt:done"],
        })
        .expect("prune");
    assert_eq!(outcome.removed, 1);
    assert_eq!(outcome.remaining, 2);

    assert!(ledger.entry("ref:old-terminal").expect("lookup").is_none());
    assert!(
        ledger
            .entry("ref:recent-terminal")
            .expect("lookup")
            .is_some(),
        "a recent entry of a terminal attempt survives"
    );
    assert!(
        ledger.entry("ref:old-live").expect("lookup").is_some(),
        "a live attempt's entry survives no matter how old"
    );
}

/// The documented cost of pruning, asserted rather than merely claimed.
#[test]
fn a_pruned_reference_is_delivered_again() {
    let private = PrivateLedger::new();
    let mut ledger = CancelLedger::open(private.path()).expect("open ledger");
    ledger
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:done",
            observed_sequence: 1,
            requested_at_ms: 100,
        })
        .expect("first delivery");
    let outcome = ledger
        .prune(Retention {
            older_than_ms: 500,
            terminal_attempts: &["attempt:done"],
        })
        .expect("prune");
    assert_eq!(outcome.removed, 1);
    drop(ledger);

    // Forgotten, not remembered as already delivered. This is the honest cost:
    // idempotency holds only while an entry is live.
    let mut reopened = CancelLedger::open(private.path()).expect("reopen ledger");
    let receipt = reopened
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:done",
            observed_sequence: 1,
            requested_at_ms: 700,
        })
        .expect("post-prune delivery");
    assert_eq!(
        receipt.disposition,
        CancelDisposition::Delivered,
        "a pruned reference is forgotten, not replayed"
    );
    assert_eq!(reopened.entry_count().expect("count"), 1);
}

#[test]
fn pruning_with_no_terminal_attempts_removes_nothing() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:a",
            observed_sequence: 1,
            requested_at_ms: 100,
        })
        .expect("first delivery");

    let outcome = ledger
        .prune(Retention {
            older_than_ms: i64::MAX,
            terminal_attempts: &[],
        })
        .expect("empty prune");
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.remaining, 1);
}

#[test]
fn a_prune_with_a_malformed_horizon_or_attempt_is_refused() {
    let (_private, mut ledger) = ledger();
    ledger
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:a",
            observed_sequence: 1,
            requested_at_ms: 100,
        })
        .expect("first delivery");

    let error = ledger
        .prune(Retention {
            older_than_ms: -1,
            terminal_attempts: &["attempt:a"],
        })
        .expect_err("horizon refusal");
    assert_eq!(error.category(), "invalid_field");
    assert!(error.to_string().contains("older_than_ms"));

    let error = ledger
        .prune(Retention {
            older_than_ms: 500,
            terminal_attempts: &["attempt:a", ""],
        })
        .expect_err("attempt grammar refusal");
    assert_eq!(error.category(), "invalid_field");

    let attempts: Vec<String> = (0..=1_024)
        .map(|index| format!("attempt:{index}"))
        .collect();
    let borrowed: Vec<&str> = attempts.iter().map(String::as_str).collect();
    let error = ledger
        .prune(Retention {
            older_than_ms: 500,
            terminal_attempts: &borrowed,
        })
        .expect_err("list bound refusal");
    assert_eq!(error.category(), "invalid_field");

    assert_eq!(
        ledger.entry_count().expect("count"),
        1,
        "no refused prune may have deleted anything"
    );
}

#[test]
fn pruning_frees_capacity_for_new_entries() {
    let private = PrivateLedger::new();
    let mut ledger =
        CancelLedger::open_with_capacity(private.path(), 1).expect("open bounded ledger");
    ledger
        .record(CancelRequest {
            request_ref: "ref:a",
            attempt_id: "attempt:done",
            observed_sequence: 1,
            requested_at_ms: 100,
        })
        .expect("first delivery");
    let error = ledger
        .record(request("ref:b", "attempt:live", 1))
        .expect_err("capacity refusal");
    assert_eq!(error.category(), "ledger_full");

    ledger
        .prune(Retention {
            older_than_ms: 500,
            terminal_attempts: &["attempt:done"],
        })
        .expect("prune");
    let receipt = ledger
        .record(request("ref:b", "attempt:live", 1))
        .expect("delivery after prune");
    assert_eq!(receipt.disposition, CancelDisposition::Delivered);
}
